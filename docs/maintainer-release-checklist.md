# Maintainer release checklist

- Protect `main` and require CI before merge.
- Review CodeQL and security checks before release.
- Do not make direct unreviewed release changes where account controls support review.
- Build the wheel and source distribution, install the wheel in a clean environment, and run `horustrace --help`, `horustrace rules --format json`, and a secure fixture scan.
- Create a signed tag manually when signing is configured; do not claim a signature otherwise.
