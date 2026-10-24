# Example Vagrantfile that consumes the box built by Packer.
#   vagrant box add --name p4-ubuntu2204 builds/p4-ubuntu2204-0.1.0-virtualbox.box
Vagrant.configure("2") do |config|
  config.vm.box = "p4-ubuntu2204"
  config.vm.hostname = "p4"
  config.ssh.forward_x11 = true

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 4
    vb.memory = 4096
    # bmv2 / mininet traffic needs promiscuous mode on extra NICs
    vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
  end

  config.vm.synced_folder ".", "/vagrant"
end
