# JsJaws Service
This Assemblyline service integrates components of the open-source project [Malware Jail](https://github.com/HynekPetrak/malware-jail), which provides a sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction.

## Signatures
In the `signatures` folder are a bunch of signatures that will affect the scoring of samples. If you have a sample that
needs better detection from this service and you see output from MalwareJail tool (or in the `output.txt`) that could 
have a signature written for it, then please make a Pull Request or share the sample! Let's improve this!

## Submission Parameters
* `browser`: Browser type for detonation.
* `wscript_only`: By default, detonation takes place within a sandboxed browser. This option allows for the sample to be run in WScript only.
* `throw_http_exc`: By selecting the throw_http_exc flag, the sandbox will throw an error in every network call. This is useful for attempting different code execution paths.
* `download_payload`: If the service should allow the sample to download any payload from the Internet.
* `extract_function_calls`: Files that each represent a Function Call can be noisy and not particularly useful. This flag turns on this extraction.
* `extract_eval_calls`: Files that each represent a Eval Call can be noisy and not particularly useful. This flag turns on this extraction.
