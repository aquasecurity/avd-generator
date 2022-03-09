package main

var crossOver = map[string]string{
	"AVD-AWS-0007": "en/aws/athena/workgroup-enforce-configuration.md",
	"AVD-AWS-0006": "en/aws/athena/workgroup-encrypted.md",
	"AVD-AWS-0012": "en/aws/cloudfront/cloudfront-https-only.md",
	"AVD-AWS-0010": "en/aws/cloudfront/cloudfront-logging-enabled.md",
	"AVD-AWS-0013": "en/aws/cloudfront/insecure-cloudfront-protocols.md",
	"AVD-AWS-0011": "en/aws/cloudfront/cloudfront-waf-enabled.md",
	"AVD-AWS-0015": "en/aws/cloudtrail/cloudtrail-encryption.md",
	"AVD-AWS-0016": "en/aws/cloudtrail/cloudtrail-file-validation.md",
	"AVD-AWS-0014": "en/aws/cloudtrail/cloudtrail-enabled.md",
	"AVD-AWS-0025": "en/aws/dynamodb/dynamodb-kms-encryption.md",
	"AVD-AWS-0028": "en/aws/ec2/insecure-ec2-metadata-options.md",
	"AVD-AWS-0031": "en/aws/ecr/ecr-repository-tag-immutability.md",
	"AVD-AWS-0037": "en/aws/efs/efs-encryption-enabled.md",
	"AVD-AWS-0040": "en/aws/eks/eks-private-endpoint.md",
	"AVD-AWS-0038": "en/aws/eks/eks-logging-enabled.md",
	"AVD-AWS-0041": "en/aws/eks/eks-security-groups.md",
	"AVD-AWS-0047": "en/aws/elb/insecure-ciphers.md",
	"AVD-AWS-0054": "en/aws/elb/elb-https-only.md",
	"AVD-AWS-0123": "en/aws/iam/users-mfa-enabled.md",
	"AVD-AWS-0062": "en/aws/iam/maximum-password-age.md",
	"AVD-AWS-0058": "en/aws/iam/password-requires-lowercase.md",
	"AVD-AWS-0061": "en/aws/iam/password-requires-uppercase.md",
	"AVD-AWS-0063": "en/aws/iam/minimum-password-length.md",
	"AVD-AWS-0060": "en/aws/iam/password-requires-symbols.md",
	"AVD-AWS-0056": "en/aws/iam/password-reuse-prevention.md",
	"AVD-AWS-0059": "en/aws/iam/password-requires-numbers.md",
	"AVD-AWS-0064": "en/aws/kinesis/kinesis-streams-encrypted.md",
	"AVD-AWS-0065": "en/aws/kms/kms-key-rotation.md",
	"AVD-AWS-0080": "en/aws/rds/rds-encryption-enabled.md",
	"AVD-AWS-0082": "en/aws/rds/rds-publicly-accessible.md",
	"AVD-AWS-0084": "en/aws/redshift/redshift-cluster-cmk-encryption.md",
	"AVD-AWS-0089": "en/aws/s3/s3-bucket-logging.md",
	"AVD-AWS-0086": "en/aws/s3/s3-bucket-all-users-acl.md",
	"AVD-AWS-0090": "en/aws/s3/s3-bucket-versioning.md",
	"AVD-AWS-0095": "en/aws/sns/sns-topic-encrypted.md",
	"AVD-AWS-0096": "en/aws/sqs/sqs-encrypted.md",
	"AVD-AZU-0001": "en/azure/appservice/client-certificates-enabled.md",
	"AVD-AZU-0004": "en/azure/appservice/https-only-enabled.md",
	"AVD-AZU-0002": "en/azure/appservice/identity-enabled.md",
	"AVD-AZU-0005": "en/azure/appservice/http-2.0-enabled.md",
	"AVD-AZU-0003": "en/azure/appservice/authentication-enabled.md",
	"AVD-AZU-0006": "en/azure/appservice/tls-version-check.md",
	"AVD-AZU-0014": "en/azure/keyvault/key-expiration-enabled.md",
	"AVD-AZU-0031": "en/azure/monitor/log-profile-retention-policy.md",
	"AVD-AZU-0045": "en/azure/securitycenter/standard-pricing-enabled.md",
	"AVD-AZU-0044": "en/azure/securitycenter/high-severity-alerts-enabled.md",
	"AVD-AZU-0046": "en/azure/securitycenter/security-contacts-enabled.md",
	"AVD-GCP-0030": "en/google/compute/instance-level-ssh-only.md",
	"AVD-GCP-0032": "en/google/compute/connect-serial-ports-disabled.md",
	"AVD-GCP-0042": "en/google/compute/os-login-enabled.md",
	"AVD-GCP-0013": "en/google/dns/dns-security-enabled.md",
	"AVD-GCP-0012": "en/google/dns/dns-security-signing-algorithm.md",
	"AVD-GCP-0008": "en/google/iam/service-account-separation.md",
	"AVD-GCP-0065": "en/google/iam/service-account-key-rotation.md",
	"AVD-GCP-0017": "en/google/sql/db-publicly-accessible.md",
	"AVD-GCP-0024": "en/google/sql/db-automated-backups.md",
}

var reverseCrossOver map[string]string

func init() {
	reverseCrossOver = make(map[string]string)

	for avdID, cspmPath := range crossOver {
		reverseCrossOver[cspmPath] = avdID
	}
}

func getAVDIDByCSPMPath(path string) string {

	if id, ok := reverseCrossOver[path]; ok {
		return id
	}
	return ""
}
