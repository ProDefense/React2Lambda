#!/usr/bin/env bash
set -euo pipefail

# Deploy Next.js 15.0.4 (vulnerable) to Lambda using OpenNext (no SST)
export AWS_REGION="${AWS_REGION:-us-east-2}"
APP_DIR="${1:-next-opennext-hello}"
FN_NAME="${2:-nextjs-opennext}"
ROLE_NAME="${FN_NAME}-role"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

# Create Next.js app if needed
[ ! -d "$APP_DIR" ] && npx --yes create-next-app@latest "$APP_DIR" --yes
cd "$APP_DIR"

# Install vulnerable version and OpenNext
npm install next@15.0.4 react@19 react-dom@19
npm install --save-dev open-next@^3.0.0

# Minimal app files
mkdir -p app
cat > app/layout.tsx <<'EOF'
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html><body>{children}</body></html>;
}
EOF
cat > app/page.tsx <<'EOF'
export default function Page() {
  return <h1>Hello</h1>;
}
EOF
cat > next.config.js <<'EOF'
module.exports = { output: "standalone", eslint: { ignoreDuringBuilds: true } };
EOF
cat > open-next.config.mjs <<'EOF'
const config = {
  default: {
    runtime: "nodejs20.x",
    converter: "aws-apigw-v2",
    wrapper: "aws-lambda"
  }
};
export default config;
EOF

# Build with OpenNext
npm pkg set scripts.open-next-build="open-next build"
npm run open-next-build

# Zip Lambda artifact
ARTIFACT_ZIP="/tmp/${FN_NAME}.zip"
rm -f "$ARTIFACT_ZIP"
(cd .open-next/server-functions/default && zip -r "$ARTIFACT_ZIP" . >/dev/null)

# IAM role
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null
  sleep 10
fi
ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)"

# Lambda function
if aws lambda get-function --function-name "$FN_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FN_NAME" --zip-file "fileb://${ARTIFACT_ZIP}" --region "$AWS_REGION" >/dev/null
  aws lambda wait function-updated --function-name "$FN_NAME" --region "$AWS_REGION"
else
  until aws lambda create-function --function-name "$FN_NAME" --runtime nodejs20.x \
    --handler index.handler --role "$ROLE_ARN" --zip-file "fileb://${ARTIFACT_ZIP}" \
    --timeout 30 --memory-size 1024 --region "$AWS_REGION" >/dev/null 2>&1; do sleep 5; done
fi

# Function URL
aws lambda create-function-url-config --function-name "$FN_NAME" --auth-type NONE \
  --region "$AWS_REGION" >/dev/null 2>&1 || \
aws lambda update-function-url-config --function-name "$FN_NAME" --auth-type NONE \
  --region "$AWS_REGION" >/dev/null

# Permissions
aws lambda remove-permission --function-name "$FN_NAME" --statement-id FunctionURLAllowPublicAccess \
  --region "$AWS_REGION" 2>/dev/null || true
aws lambda add-permission --function-name "$FN_NAME" --statement-id FunctionURLAllowPublicAccess \
  --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE \
  --region "$AWS_REGION" >/dev/null
aws lambda remove-permission --function-name "$FN_NAME" --statement-id FunctionURLInvokeAllowPublicAccess \
  --region "$AWS_REGION" 2>/dev/null || true
aws lambda add-permission --function-name "$FN_NAME" --statement-id FunctionURLInvokeAllowPublicAccess \
  --action lambda:InvokeFunction --principal "*" --invoked-via-function-url \
  --region "$AWS_REGION" >/dev/null

# Output URL
URL="$(aws lambda get-function-url-config --function-name "$FN_NAME" --region "$AWS_REGION" --query FunctionUrl --output text)"
echo "Lambda URL: $URL"
