# Transformer: Machine learning

Use this transformer to add more directives and help to train your machine learning models.

Options:

* `add-features` (bool)
  > enable all features

Default values:

```yaml
transforms:
  machine-learning:
    add-features: true
```

Specific directive(s) available for the text format:

* `ml-entropy`: entropy of the query name
* `ml-length`: length of the query name
* `ml-digits`: number of digits
* `ml-lowers`: number of letters in lowercase
* `ml-uppers`: number of letters in uppercase
* `ml-specials`: number of specials letters like dot, dash
* `ml-others`: number of unprintable characters
* `ml-labels`: number of labels
* `ml-ratio-digits`:  ratio of the number digits with total number of characters
* `ml-ratio-letters`: ratio of the number letters with total number of characters
* `ml-ratio-specials`: ratio of the number specials with total number of characters
* `ml-ratio-others`: ratio of the number others characters with total number of characters
* `ml-consecutive-chars`: number of consecutive characters
* `ml-consecutive-vowels`: number of consecutive vowels
* `ml-consecutive-digits`: number of consecutive digits
* `ml-consecutive-consonants`: number of consecutive consonants
* `ml-size`: size of the packet
* `ml-occurences`: number of repetition of the packet
* `ml-uncommon-qtypes`: flag for uncommon qtypes
