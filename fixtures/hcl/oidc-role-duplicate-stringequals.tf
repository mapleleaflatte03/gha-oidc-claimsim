# Fixture reproducing Datadog Security Labs / UK GDS class:
# duplicate Condition.StringEquals keys in jsonencode() silently drop `sub`.
# Source: https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/
# HCSEC-2023-26: https://discuss.hashicorp.com/t/hcsec-2023-26-terraforms-handling-of-duplicate-map-keys-in-configurations-may-have-security-implications/57613
#
# NOT applied — dry-run / parse-only fixture for Gate C.

resource "aws_iam_role" "github_actions_deploy" {
  name = "github-actions-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:sub" = "repo:acme/payments:ref:refs/heads/main"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}
