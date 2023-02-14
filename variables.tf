variable "service_name" {
  description = "tagged with service name"
}
variable "aws_profile" {
  description = "aws profile name"
}
variable "domain_names" {
  description = "domain names"
  type        = list(string)
}
variable "cloudfront_origin_path" {
  default     = ""
  description = "Origin path of CloudFront"
}
variable "route53_zone_id" {
  description = "Route53 Zone ID"
}
variable "s3_bucket_name" {
  description = "S3 bucket name"
}
variable "save_access_log" {
  description = "whether save cloudfront access log to S3"
  type        = bool
  default     = false
}
variable "lambda_function_associations" {
  description = "CloudFront Lambda function associations. key is CloudFront event type and value is lambda function ARN with version"
  type        = map(string)
  default     = {}
}
variable "cors_allowed_origins" {
  description = "CORS allowed origins"
  type        = list(string)
  default     = []
}

# Manage redirections
variable "redirect" {
  type        = bool
  default     = false
  description = "Redirect requests for an object/URL?"
}

variable "redirect_destination" {
  type        = string
  default     = ""
  description = "Target bucket website address or personal domain"
}
