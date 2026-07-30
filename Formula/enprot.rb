class Enprot < Formula
  desc "Engyon Protected Text — confidentiality and provenance for text"
  homepage "https://www.engyon.org"
  url "https://github.com/engyon/enprot/archive/refs/tags/v0.5.11.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "BSD-2-Clause"
  head "https://github.com/engyon/enprot.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "rust" => :build
  depends_on "botan"
  depends_on "rnp"

  def install
    system "cargo", "install", *std_cargo_args(path: "."), "--features", "vendored-rnp"
  end

  test do
    assert_match "enprot #{version}", shell_output("#{bin}/enprot --version")
  end
end
