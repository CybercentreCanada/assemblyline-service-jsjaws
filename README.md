# JsJaws Service
This Assemblyline service integrates components from three open-source projects:
* [Malware Jail](https://github.com/HynekPetrak/malware-jail), which provides a sandbox for semi-automatic Javascript 
  malware analysis, deobfuscation and payload extraction.
* [Box.js](https://github.com/CapacitorSet/box-js), which is a sandbox tool for studying JavaScript malware.
* [JS-X-Ray](https://github.com/NodeSecure/js-x-ray), which is a tool for static analysis via SAST scanning.

Both sandboxes use [Node VM](https://nodejs.org/api/vm.html) under the hood for malware sandboxing, although Box.js prefers a 
modified version of Node VM called [vm2](https://github.com/patriksimek/vm2). 

## Signatures
JsJaws also uses signatures for the majority of its scoring. These can be run on both the file contents and the sandbox 
outputs. 

In the `signatures` folder are a bunch of signatures that will affect the scoring of samples. If you have a sample that
needs better detection from this service, and you see output from the MalwareJail or Box.js tool that could 
have a signature written for it, then please make a Pull Request or share the sample! Let's improve this!

## Submission Parameters
Service-wide parameters:
* `tool_timeout`: The length of time we will allow both Malware Jail and Box.js to individually run for.
* `add_supplementary`: If you want supplementary files to be added to the result, select this.
* `static_signatures`:  If you want the signatures to be run against the file contents as well rather than just the 
  dynamic excecution output.
* `display_sig_marks`: If you want the lines of code that caused the signatures to be raised to be displayed in the 
  ResultSections.

Box.js parameters:
* `no_shell_error`: For Box.js, select this flag if you want to.

MalwareJail parameters:
* `browser`: Browser type for detonation.
* `wscript_only`: By default, detonation takes place within a sandboxed browser. This option allows for the sample to 
  be run in WScript only.
* `throw_http_exc`: By selecting the throw_http_exc flag, the sandbox will throw an error in every network call. This 
  is useful for attempting different code execution paths.
* `download_payload`: If the service should allow the sample to download any payload from the Internet.
* `extract_function_calls`: Files that each represent a Function Call can be noisy and not particularly useful. This 
  flag turns on this extraction.
* `extract_eval_calls`: Files that each represent a Eval Call can be noisy and not particularly useful. This flag turns 
  on this extraction.
  
## Features included with Internet connectivity
### jQuery Fetching
There have been samples that embed malicious code within standard jQuery libraries. If the service Docker container has 
access to the Internet, then we can fetch the actual jQuery library and compare the two files, determining the 
difference between them and then extracting the difference (aka malicious code). If the service Docker container 
does not have Internet access, then please set the `docker_config` value of `allow_internet_access` to `False` in the 
`service_manifest.yml`.
