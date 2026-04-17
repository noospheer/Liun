# Homebrew formula — drop into a tap repo (e.g. homebrew-tap).
# Builds from source; binary distribution requires publishing the release
# tarball to a publicly-fetchable URL and filling in the sha256.

class LiunNode < Formula
  desc "ITS-secure network node"
  homepage "https://github.com/YOUR-ORG/liun-node"
  url "https://github.com/YOUR-ORG/liun-node/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "__FILL_IN_TARBALL_SHA256__"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--locked", "--release",
           "--bin", "liun-node",
           "--bin", "chat",
           "--bin", "relay",
           "--bin", "groupchat"
    bin.install "target/release/liun-node"
    bin.install "target/release/chat"      => "liun-chat"
    bin.install "target/release/relay"     => "liun-relay"
    bin.install "target/release/groupchat" => "liun-groupchat"
  end

  def caveats
    <<~EOS
      liun-node requires a CPU with RDSEED for the full ITS claim.
      Without it, runs in computational-CSPRNG mode — see docs/SECURITY.md
      and docs/THREAT_MODEL.md.

      macOS has no systemd; use a launchd plist under ~/Library/LaunchAgents
      or run manually. See docs/DEPLOYMENT.md.
    EOS
  end

  test do
    # Minimum smoke test: binary runs and prints usage.
    assert_match "Usage", shell_output("#{bin}/liun-node --help", 2)
  end
end
