# shim-review-bot

This is a bot that can help you review [shim](https://github.com/rhboot/shim-review).

# Apply workflow

```yaml
name: Issue comment
on:
  issue_comment:
    types: [created, edited]
jobs:
  review_comment:
    if: contains(github.event.comment.body, '/review-bot ')
    runs-on: ubuntu-latest
    steps:
      - uses: "DamianReeves/write-file-action@master"
        with:
          path: /tmp/comment.txt
          write-mode: overwrite
          contents: ${{ github.event.comment.body }}
      - run: |
          echo "BODY:"
          cat /tmp/comment.txt
      - uses: jc-lab/shim-review-bot@master
        with:
          comment-file: /tmp/comment.txt
          issue-repository: ${{ github.repository }}
          issue-number: ${{ github.event.issue.number }}
          source: ${{ inputs.source }}
          build-script: ${{ inputs.build-script }}
          output-file: ${{ inputs.output-file }}
          vendor-cert: ${{ inputs.vendor-cert }}
          report-output: ${{ inputs.report-output }}
```

# Comment format

```
/review-bot SOURCE
\``` (optional)
build-script: build.sh
output-file: output.tar
vendor-cert: vendor_cert.der
sbat: sbat.csv
\```
```

# Review Repository

## Required Files

- Dockerfile (overridable by `build-script` and `output` parameter)
- vendor_cert.der (overridable by `vendor-cert` parameter)
- sbat.csv (overridable by `sbat` parameter)

Sample review directory: https://github.com/jc-lab/shim-review-bot/tree/master/sample-repo
(need sbat.csv, vendor certificate, and Dockerfile.)

## Dockerfile format

After built:

```dockerfile
RUN echo "::review hash-start" && \
    for name in $(find YOUR_OUTPUT_DIRECTORY -type f -name "shim*.efi"); do sha256sum $name; done && \
    echo "::review hash-end"
```