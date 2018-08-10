{
  "targets": [{
    "target_name": "bf_custom",
    "include_dirs" : [
      "src",
      "<!(node -e \"require('nan')\")"
    ],
    "sources": [
      "src/index.cc",
      "src/BlowFish.cc"
    ]
  }]
}