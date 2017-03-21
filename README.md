# Perf-JitDump-Agent

## Build

    cd perf-jitdump-agent
    mvn package
    
    cd target
    make install # Will create a directory named jitdump in the project home directory with required scripts and libraries

## Usage

The agent can either be loaded on JVM start or attached to an already running JVM.

When loading the agent the following options are available and can be set on the 
[command line](http://docs.oracle.com/javase/8/docs/platform/jvmti/jvmti.html#starting). 

    verbose=[0-5]      0 is off, and 5 is trace level, by default logging is off.
    directory=<PATH>   Location to store JitDump file, byt default $HOME/.debug/jit.
    duration=<seconds> How long to record method compilation to the jitdump file, by default infinite (-1).

When attaching to an already running JVM use `<PATH>/jitdump/bin/jitdump -p <PID>`, the attach mechanism supports the 
same options as when loading the agent, run `<PATH>/jitdump/bin/jitdump -h` for details.

### Recording and Analyzing

1. Start Java application (and load agent if you want to be able to start recording directly).
    * For correct stack unwinding and maximum information available for the agent add the following options.
        * `-XX:+PreserveFramePointer -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints`
        * Instead of `-XX:+PreserveFramePointer` the perf recording can on modern hardware use the `-call-graph lbr` option to gather stack traces.
    * Ensure that duration is infinite or longer than your intended recording to ensure all compiled methods are registered correctly.
2. Attach agent unless loaded at start, `<PATH>/jitdump/bin/jitdump -p <PID>` 
    * Ensure that duration is infinite or longer than your intended recording to ensure all compiled methods are registered correctly.
3. `perf record -g -k 1 -p <PID>`
4. `perf inject -j -i perf.data -o perf.jit.data`
5. Unpack your Java source code to the current directory to enable `perf report` to find it correctly.
    * Don't forget `<JAVA_HOME>/src.zip`
6. `perf report --source --no-children -i perf.jit.data`

### Linux Perf Support

Not all distributions will support the -j/--jit flag with the shipped version of perf. On Ubuntu 16.04 for example, the 
man page mentions the flag but the binary does not recognize it. However the recording can still be done with the 
version shipped with the distribution, but the inject step requires a self compiled binary with support for the jit 
option. Compiling perf is rather straight forward, pull the latest Linux source code and enter the the 
`linux/tools/perf` directory and run `make`. Depending on your system you might need to install one or more required 
libraries for a successful compilation.

## License

This program is licensed under GPLv2. See the LICENSE file.

