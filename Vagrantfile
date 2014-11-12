VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "phusion-open-ubuntu-12.04-amd64"
  config.vm.box_url = "https://oss-binaries.phusionpassenger.com/vagrant/boxes/ubuntu-12.04.3-amd64-vbox.box"
  config.ssh.forward_agent = true
  config.vm.network "public_network"

  go_cmd = <<SCRIPT
echo Installing GO
cd /tmp && wget https://storage.googleapis.com/golang/go1.3.3.linux-amd64.tar.gz
tar zxvf /tmp/go*tar.gz -C /opt
echo 'export GOROOT=/opt/go' > /etc/profile.d/go.sh
echo 'export PATH=$PATH:$GOROOT/bin' >> /etc/profile.d/go.sh
echo Installing build tools
apt-get -y update
apt-get -y install build-essential git mercurial
SCRIPT

  config.vm.provision 'shell', inline: go_cmd
end
