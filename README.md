# drone-aws-oidc

A Drone/Harness CI plugin that exchanges an OIDC token for temporary AWS credentials using AWS STS `AssumeRoleWithWebIdentity`. The retrieved credentials are exported as secrets available to subsequent pipeline steps.

## Usage

```yaml
- step:
    type: Plugin
    name: AWS OIDC
    identifier: aws_oidc
    spec:
      connectorRef: account.harnessImage
      image: harnesssecure/aws-oidc:latest
      settings:
        iamrolearn: arn:aws:iam::123456789012:role/my-role
        oidc_token_id: <+secrets.getValue("oidc_token")>
        duration: 3600
        role_session_name: my-session
```

## Settings

| Setting              | Environment Variable        | Required | Default              | Description                                      |
|----------------------|-----------------------------|----------|----------------------|--------------------------------------------------|
| `iamrolearn`         | `PLUGIN_IAMROLEARN`         | Yes      |                      | The ARN of the IAM role to assume                |
| `oidc_token_id`      | `PLUGIN_OIDC_TOKEN_ID`      | Yes      |                      | The OIDC token used to authenticate              |
| `duration`           | `PLUGIN_DURATION`           | No       |                      | Session duration in seconds (AWS default: 3600)  |
| `role_session_name`  | `PLUGIN_ROLE_SESSION_NAME`  | No       | `harness-aws-oidc`   | A name for the assumed role session              |
| `log_level`          | `PLUGIN_LOG_LEVEL`          | No       |                      | Log verbosity: `debug` or `trace`                |

## Output Variables

The plugin writes temporary AWS credentials to the Harness output secret file (`HARNESS_OUTPUT_SECRET_FILE`). These are available as secret output variables in subsequent pipeline steps:

| Variable                | Description                          |
|-------------------------|--------------------------------------|
| `AWS_ACCESS_KEY_ID`     | Temporary access key ID              |
| `AWS_SECRET_ACCESS_KEY` | Temporary secret access key          |
| `AWS_SESSION_TOKEN`     | Session token for temporary credentials |

### Referencing outputs in subsequent steps

Use Harness expressions to reference the credentials in later steps:

```
<+steps.aws_oidc.output.outputVariables.AWS_ACCESS_KEY_ID>
<+steps.aws_oidc.output.outputVariables.AWS_SECRET_ACCESS_KEY>
<+steps.aws_oidc.output.outputVariables.AWS_SESSION_TOKEN>
```

## Building

```bash
./scripts/build.sh
```

## Docker

```bash
docker build -f docker/Dockerfile -t harnesssecure/aws-oidc .
```
