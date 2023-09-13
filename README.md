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