---
category: minorAnalysis
---
* Fixed labels in the API graph pertaining to definitions of subscripts. Previously, these were found by `getMember` rather than `getASubscript`.
* Added edges for indices of subscripts to the API graph. Now a subscripted API node will have an edge to the API node for the index expression. So if `foo` is matched by API node `A`, then `"key"` in `foo["key"]` will be matched by the API node `A.getIndex()`. This can be used to track the origin of the index.
* Added member predicate `getSubscriptAt(API::Node index)` to `API::Node`. Like `getASubscript()`, this will return an API node that matches a subscript of the node, but here it will be restricted to subscripts where the index matches the `index` parameter.
* Added convenience predicate `getSubscript("key")` to obtain a subscript at a specific index, when the index happens to be a statically known string.
