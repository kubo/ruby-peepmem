# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'peepmem/version'

Gem::Specification.new do |spec|
  spec.name          = "peepmem"
  spec.version       = Peepmem::VERSION
  spec.authors       = ["Kubo Takehiro"]
  spec.email         = ["kubo@jiubao.org"]
  spec.extensions    = ["ext/peepmem/extconf.rb"]
  spec.summary       = %q{Peep memory of another process.}
  spec.homepage      = "https://github.com/kubo/ruby-peepmem"
  spec.license       = "2-clause BSD-style"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rake-compiler"
end
