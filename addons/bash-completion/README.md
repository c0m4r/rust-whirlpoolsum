```bash
sudo wget -O /usr/share/bash-completion/completions/whirlpoolsum https://raw.githubusercontent.com/c0m4r/rust-whirlpoolsum/refs/heads/main/addons/bash-completion/whirlpoolsum
echo "41d296afe30e0ec5feab005f9f5830eb5bd10cfbf06cc86e59ae489fc3e6c73b8fc944cb8205e565ab26c94f87dc290cb0ee157c68c0d932191b3ac2d892d65d  whirlpoolsum" | whirlpoolsum -c || sudo rm -f /usr/share/bash-completion/completions/whirlpoolsum
source /usr/share/bash-completion/bash_completion
```
