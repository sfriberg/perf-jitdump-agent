/*
 *   Perf-JitDump-Agent: Create jitdump files supported by Linux Perf.
 *   Copyright (C) 2017 Staffan Friberg <sfriberg@kth.se>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package jitdump;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Paths;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.EnumConverter;

import static java.util.Arrays.asList;

/**
 * Simple Java application to attach and load a agent library to a running JVM using a PID.
 */
public class Main {

	// Determine the location of the JAR file containing this class
	private final static String JAR_LOCATION = Main.class.getClassLoader()
					.getResource(Main.class.getName().replace('.', '/') + ".class")
					.getPath().split("!")[0].replace("file:", "");

	/**
	 * Verbose levels for the agent.
	 */
	private enum Verbose {
		OFF(0),
		ERROR(1),
		WARN(2),
		INFO(3),
		DEBUG(4),
		TRACE(5);

		private final int value;

		private Verbose(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}
	};

	/**
	 * Simple return value translation from the JIT dump native agent.
	 *
	 * @param return_value return value to convert
	 * @return String describing the error
	 */
	private static String getDescription(int return_value) {
		switch (return_value) {
			case 0:
				return "Success";
			case -1:
				return "General error";
			case -30:
				return "JitDump is already active";
			case -31:
				return "Error creating JitDump file";
			default:
				return "Unknown error";
		}
	}

	/**
	 * Attach native JVMTI library to specified Java process.
	 *
	 * @param argv command line arguments
	 * @throws IOException
	 * @throws AttachNotSupportedException
	 * @throws AgentLoadException
	 * @throws AgentInitializationException
	 */
	public static void main(String... argv)
					throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

		OptionParser parser = new OptionParser();
		OptionSpec<Integer> pid = parser.acceptsAll(asList("p", "pid")).withRequiredArg().ofType(Integer.class).required()
						.describedAs("PID of the process to attach agent to");
		OptionSpec<Verbose> verbose = parser.acceptsAll(asList("v", "verbose")).withRequiredArg().ofType(Verbose.class)
						.withValuesConvertedBy(new EnumConverter<Verbose>(Verbose.class) {
						}).defaultsTo(Verbose.OFF).describedAs("Logging level for the native agent");
		OptionSpec<Void> version = parser.acceptsAll(asList("V", "version")).forHelp();
		OptionSpec<String> directory = parser.acceptsAll(asList("directory")).withRequiredArg().ofType(String.class)
						.defaultsTo(System.getProperty("user.home") + "/.debug/jit").describedAs("Directory to store jitdump");
		OptionSpec<Long> duration = parser.acceptsAll(asList("d", "duration")).withRequiredArg().ofType(Long.class)
						.defaultsTo(-1L).describedAs("Duration of recording method compilation to jitdump");
		OptionSpec<String> library = parser.acceptsAll(asList("l", "library")).withRequiredArg().ofType(String.class)
						.defaultsTo(Paths.get(JAR_LOCATION).resolve("libperfjitdump.so").toAbsolutePath().toString())
						.describedAs("Full path to the libperfjitdump.so");
		OptionSpec<Void> help = parser.acceptsAll(asList("h", "help")).forHelp();

		try {
			OptionSet options = parser.parse(argv);

			if (options.has(help)) {
				parser.printHelpOn(System.out);
				return;
			}

			if (options.has(version)) {
				Package pkg = Main.class.getPackage();
				System.out.println(pkg.getImplementationTitle() + " " + pkg.getImplementationVersion());
				return;
			}

			// Build option string for the agent libarary
			StringBuilder agent_options = new StringBuilder();
			if (options.has(verbose)) {
				agent_options.append("verbose=").append(options.valueOf(verbose).getValue()).append(',');
			}
			if (options.has(duration)) {
				agent_options.append("duration=").append(options.valueOf(duration)).append(',');
			}
			if (options.has(directory)) {
				agent_options.append("directory=").append(options.valueOf(directory)).append(',');
			}

			VirtualMachine vm = VirtualMachine.attach(options.valueOf(pid).toString());
			try (Closeable ac = vm::detach) {
				vm.loadAgentPath(options.valueOf(library), agent_options.toString());
			} catch (AgentInitializationException ex) {
				System.err.println("Error attaching agent : " + getDescription(ex.returnValue()));
				throw ex;
			}

		} catch (OptionException e) {
			System.err.println(e.getMessage());
			parser.printHelpOn(System.err);
			System.exit(1);
		}
	}
}
