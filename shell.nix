# shell.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python311
    python311Packages.pip
    python311Packages.virtualenv
    nodejs_20
    openssl
    gitAndTools.gh
    gcc.cc.lib   # libstdc++.so.6 — richiesta da greenlet (sqlalchemy async)
  ];

  shellHook = ''
    export NPM_CONFIG_PREFIX=$HOME/.npm-global
    export PATH=$HOME/.npm-global/bin:$PATH
    export LD_LIBRARY_PATH=${pkgs.gcc.cc.lib}/lib:$LD_LIBRARY_PATH

    if [ ! -d .venv ]; then
      echo "Creating virtualenv..."
      python -m venv .venv
    fi
    source .venv/bin/activate
    pip install -q -r requirements.txt

    echo "Agent Trust environment ready"
    echo "Python: $(python --version)"
    echo "Node: $(node --version)"
  '';
}
