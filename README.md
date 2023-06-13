# idaswissknife
This repo just a bunch of helper-scripts (wrapped in IDA Pro plugin in manner of [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools/) ) developed and used in daily work cases.

## Callbacks

### objc_msgSend resolver

Simple feature imitating Hopper Disassembler functionality when clicking on indirect call of objc method via objc_msgSend.
* double-click on `objc_msgSend` in HexRays pseudocode
* choose candidate to jump

![test](/img/objc_msgsend_resolve_example.png)

### Switch cases navigation

Choose the specific case code to jump in pseudocode.
* right-click anywhere inside of switch construction and `Get cases of switch`
* choose case to jump

![test](/img/case_navigating_exmample.png)


### Show outgoing calls

Similar to `xref from` feature, but shows only first layer of called functions (helpers like BYTE, WORD, DWORD, etc. excluded).
* right-click anywhere inside of function
* choose function call

![test](/img/outgoing_calls.png)
