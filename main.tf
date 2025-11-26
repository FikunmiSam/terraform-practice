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
    associate_public_ip_address = true
    key_name = aws_key_pair.ccem_key.key_name
    
        user_data = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y amazon-efs-utils openssh-server unzip

              # Wait for EFS to be available
              sleep 30

              # Mount EFS to /mnt/efs
              mkdir -p /mnt/efs
              echo "$${aws_efs_file_system.ccem-efs.id}:/ /mnt/efs efs _netdev,tls 0 0" >> /etc/fstab
              mount -a

              # Wait for file to be copied
              while [ ! -f /tmp/standalone.zip ]; do
                sleep 5
              done

              # Copy and extract standalone.zip to EFS
              cp /tmp/standalone.zip /mnt/efs/standalone.zip
              unzip /mnt/efs/standalone.zip -d /mnt/efs/

              # Define number of users
              NUM_USERS=10
              
              # Array of CYCLE_FOLDERS subdirectories
              FOLDERS=("MEDA" "MEDB" "MEDC" "MEDD" "MEDE" "MEDF" "MEDG" "MEDH" "MEDI" "MEDJ")

              # Create SFTP users dynamically
              for i in $(seq 1 $NUM_USERS); do
                  USER_ID=$((1000 + i))
                  USERNAME="user$i"
                  FOLDER_INDEX=$((i - 1))
                  TARGET_FOLDER="$${FOLDERS[$FOLDER_INDEX]}"
                  CYCLE_PATH="/mnt/efs/standalone/ccem/CEM/CYCLE_FOLDERS/$TARGET_FOLDER"
                  
                  # Create user with specific UID:GID
                  groupadd -g $USER_ID $USERNAME
                  useradd -u $USER_ID -g $USER_ID -d /mnt/efs/$USERNAME -s /sbin/nologin $USERNAME
                  
                  # Create chroot directory structure (must be root-owned)
                  mkdir -p /mnt/efs/$USERNAME
                  chown root:root /mnt/efs/$USERNAME
                  chmod 755 /mnt/efs/$USERNAME
                  
                  # Create mount point for the CYCLE_FOLDER inside user's chroot
                  mkdir -p /mnt/efs/$USERNAME/data
                  
                  # Bind mount the specific CYCLE_FOLDER to user's data directory
                  echo "$CYCLE_PATH /mnt/efs/$USERNAME/data none bind 0 0" >> /etc/fstab
                  
                  # Set permissions on the CYCLE_FOLDER so user can read/write
                  chown -R $USER_ID:$USER_ID $CYCLE_PATH
                  chmod -R 755 $CYCLE_PATH
                  
                  # Setup SSH directory and keys
                  mkdir -p /mnt/efs/$USERNAME/.ssh
                  cp /home/ec2-user/.ssh/authorized_keys /mnt/efs/$USERNAME/.ssh/authorized_keys
                  chown -R $USER_ID:$USER_ID /mnt/efs/$USERNAME/.ssh
                  chmod 700 /mnt/efs/$USERNAME/.ssh
                  chmod 600 /mnt/efs/$USERNAME/.ssh/authorized_keys
              done

              # Mount all bind mounts
              mount -a

              # Configure SFTP with chroot for all users
              cat >> /etc/ssh/sshd_config <<'EOL'

              Match User user*
                  ChrootDirectory /mnt/efs/%u
                  ForceCommand internal-sftp
                  AllowTcpForwarding no
                  X11Forwarding no
                  PasswordAuthentication no
              EOL

              systemctl restart sshd
              EOF
        )

  tags = {
    Name = "SFTP-EFS-Server"
  }

  depends_on = [aws_efs_mount_target.ccem-efs-mt,
  ]
}

resource "null_resource" "upload_standalone" {
  depends_on = [aws_instance.ccem_host]

  provisioner "file" {
    source      = "${path.module}/standalone.zip"
    destination = "/tmp/standalone.zip"

    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = tls_private_key.ccem_ssh.private_key_pem
      host        = aws_instance.ccem_host.public_ip
    }
  }
}