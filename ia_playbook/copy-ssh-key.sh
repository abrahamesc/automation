for i in 5 10 15 20; do sshpass -f password.txt ssh-copy-id -o StrictHostKeyChecking=no admin@192.168.0.0$i; done
