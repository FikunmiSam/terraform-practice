terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# VPC and Networking
resource "aws_vpc" "ccem_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "ccem-vpc"
  }
}

resource "aws_subnet" "ccem_public_subnet" {
  vpc_id                  = aws_vpc.ccem_vpc.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}a"
  tags = {
    Name = "ccem-public-subnet"
  }
}

resource "aws_internet_gateway" "ccem_igw" {
  vpc_id = aws_vpc.ccem_vpc.id
  tags = {
    Name = "ccem-igw"
  }
}

resource "aws_route_table" "ccem_public_rt" {
  vpc_id = aws_vpc.ccem_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ccem_igw.id
  }
  tags = {
    Name = "ccem-public-rt"
  }
}

resource "aws_route_table_association" "ec2-efs-rta" {
  subnet_id      = aws_subnet.ccem_public_subnet.id
  route_table_id = aws_route_table.ccem_public_rt.id
}

# Security Groups
resource "aws_security_group" "ccem-sg" {
  name   = "ccem-ec2-sftp-sg"
  vpc_id = aws_vpc.ccem_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "efs-sg" {
  name   = "ccem-efs-sg"
  vpc_id = aws_vpc.ccem_vpc.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ccem-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EFS File System
resource "aws_efs_file_system" "ccem-efs" {
  creation_token = "ccem-standalone-files"
  encrypted      = true
  tags = {
    Name = "ccem-efs"
  }
}

resource "aws_efs_mount_target" "ccem-efs-mt" {
  file_system_id  = aws_efs_file_system.ccem-efs.id
  subnet_id       = aws_subnet.ccem_public_subnet.id
  security_groups = [aws_security_group.efs-sg.id]
}

# SSH Key Pair
resource "tls_private_key" "ccem_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ccem_key" {
  key_name   = var.key_name
  public_key = tls_private_key.ccem_ssh.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.ccem_ssh.private_key_pem
  filename        = var.key_name
  file_permission = "0600"
}

# EC2 Instance
resource "aws_instance" "ccem_host" {
    ami           = var.ami_id 
    instance_type = var.instance_type
    subnet_id     = aws_subnet.ccem_public_subnet.id
    vpc_security_group_ids = [aws_security_group.ccem-sg.id]
    assocciate_public_ip_address = true
    key_name = aws_key_pair.ccem_key.key_name
    
        user_data = base64encode(<<-EOT
            #!/bin/bash
            yum update -y
            amazon-linux-extras install docker -y
            yum install -y amazon-efs-utils openssh-server unzip

            systemctl start docker
            systemctl enable docker
            usermod -aG docker ec2-user

            EFS_ID=${aws_efs_file_system.ccem-efs.id}
            HOST_MOUNT_POINT="/opt"

            SFTP_JAILED_DIR="$${HOST_MOUNT_POINT}/standalone/ccem"
            FINAL_UPLOAD_DIR="$${SFTP_JAILED_DIR}/CEM"
            SFTP_USER="sftpuser"

            # Mount EFS to /opt
            mkdir -p $${HOST_MOUNT_POINT}
            echo "$${EFS_ID}:/ $${HOST_MOUNT_POINT} efs defaults,_netdev,tls 0 0" >> /etc/fstab
            mount -a

            # Move file from temp to /opt with sudo
            sudo mv /tmp/standalone.zip /opt/standalone.zip
            unzip /opt/standalone.zip -d /opt/

            # Create SFTP user
            useradd -r -s /sbin/nologin $${SFTP_USER}

            chown root:root $${SFTP_JAILED_DIR}
            chmod 755 $${FINAL_UPLOAD_DIR}

            sed -i 's/^Subsystem sftp.*/Subsystem sftp \/usr\/libexec\/openssh\/sftp-server/' /etc/ssh/sshd_config

            # Configure SFTP with SSH key auth
            cat >> /etc/ssh/sshd_config <<'EOL'

            Subsystem sftp internal-sftp

            Match User sftpuser
                ForceCommand internal-sftp
                ChrootDirectory $${SFTP_JAILED_DIR}
                AllowTcpForwarding no
                X11Forwarding no
                PasswordAuthentication no
            EOL

            systemctl restart sshd

            docker run -d \
                --name ccem-dummy \
                -p 8080:8080 \
                -v $${FINAL_UPLOAD_DIR}:/opt/ccem/standalone/ccem/CEM \
                nginx:latest
        EOT
        )

        provisioner "file" {
        source      = "standalone.zip"
        destination = "/tmp/standalone.zip"
        connection {
            type        = "ssh"
            user        = "ec2-user"
            private_key = tls_private_key.ccem_ssh.private_key_pem
            host        = self.public_ip
            }
        }

        provisioner "remote-exec" {
            inline = [
                "sudo mv /tmp/standalone.zip /opt/standalone.zip",
                "unzip /opt/standalone.zip -d /opt/"
            ]
            connection {
                type        = "ssh"
                user        = "ec2-user"
                private_key = tls_private_key.ccem_ssh.private_key_pem
                host        = self.public_ip
            }
        }

  tags = {
    Name = "SFTP-EFS-Server"
  }

  depends_on = [aws_efs_mount_target.ccem-efs-mt,
  ]
}
