# Outputs
output "ec2_public_ip" {
  value = aws_instance.ccem_host.public_ip
}

output "efs_id" {
  value = aws_efs_file_system.ccem-efs.id
}

output "ssh_key_file" {
  value = local_file.private_key.filename
}

output "sftp_connection" {
  value = "sftp -i sftp-key.pem sftpuser@${aws_instance.ccem_host.public_ip}"
}

output "ssh_connection" {
  value = "ssh -i sftp-key.pem ec2-user@${aws_instance.ccem_host.public_ip}"
}