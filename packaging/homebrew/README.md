# Homebrew tap

`brew install interlockd/tap/interlock` installs from the `interlockd/homebrew-tap` repository.

After a release is on PyPI:

```sh
python3 packaging/homebrew/make_formula.py 0.1.0 > ../homebrew-tap/Formula/interlock.rb
cd ../homebrew-tap && brew audit --strict --new Formula/interlock.rb && brew install --build-from-source Formula/interlock.rb
brew test interlock && git commit -am "interlock 0.1.0" && git push
```

The generator reads every runtime dependency's sdist and sha256 from PyPI, following exact pins (pydantic's
`pydantic-core==X`), so the formula matches the released wheel's dependency set. The formula declares a
`brew services` entry (`brew services start interlock`), though `interlock init` installs its own service.
