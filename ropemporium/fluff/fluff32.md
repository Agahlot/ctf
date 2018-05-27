# Write 4 Bytes

As the challenge states that it is similar to [write4](https://ropemporium.com/challenge/write4.html) challenge in which we have to write our payload (eg: "/bin/sh") to a memory location and give it as a parameter to the system function.

In the gadget resposible for writing 4 bytes were should be of the form _mov dword ptr [ecx], edx_.
For this we first have to control the registers _ecx_ and _edx_. *Remember that xoring a value with 0 results in the same value*.

Making a seperate function for writing values to _ecx_ , _edx_ and the _data addr_ would we helpful.
