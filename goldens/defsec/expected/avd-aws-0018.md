---
title: Codebuild - Enable Encryption
heading: Misconfiguration
icon: iac
sidebar_category: misconfig
draft: false
shortName: Enable Encryption
severity: ""

avd_page_type: defsec_page

remediations:
  - cloudformation
  - terraform


menu:
  misconfig:
    identifier: codebuild/AVD-AWS-0018
    name: Enable Encryption
    parent: aws/codebuild
---

Misconfiguration > [AWS](../../) > [Codebuild](../) > AVD-AWS-0018

### ID: AVD-AWS-0018


### CodeBuild Project artifacts encryption should not be disabled

All artifacts produced by your CodeBuild project pipeline should always be encrypted

### Impact
CodeBuild project artifacts are unencrypted

<!-- DO NOT CHANGE -->
### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.

{{< tabs groupId="remediation" >}}{{% tab name="CloudFormation" %}}
Enable encryption for CodeBuild project artifacts

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: false
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: false
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"
```
{{% /tab %}}{{% tab name="Terraform" %}}
Enable encryption for CodeBuild project artifacts

```hcl
resource "aws_codebuild_project" "good_example" {
  // other config
  
  artifacts {
    // other artifacts config
    
    encryption_disabled = false
  }
}

resource "aws_codebuild_project" "good_example" {
  // other config
  
  artifacts {
    // other artifacts config
  }
}

resource "aws_codebuild_project" "codebuild" {
  // other config
  
  secondary_artifacts {
    // other artifacts config
    
    encryption_disabled = false
  }
  
  secondary_artifacts {
    // other artifacts config
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled
        {{% /tab %}}{{< /tabs >}}

### Links
- https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html
        

