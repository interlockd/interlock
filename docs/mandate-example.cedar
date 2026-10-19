// Example mandate (.interlock/mandate.cedar). Evaluated locally by interlockd; the same policy can be attached to an
// Amazon Bedrock AgentCore Gateway policy engine for MCP tools, with the action names mapped by the bindings.

// Scope: push only to our own remotes (origin or anything under the org)
permit (principal, action == Interlock::Action::"git.push", resource)
when { context.input.remote == "origin" || context.input.remote like "github.com/my-org/*" };

// Irreversible: never rewrite a protected branch, whatever else says
forbid (principal, action == Interlock::Action::"git.push", resource)
when { context.input.force == true && (context.input.branch == "main" || context.input.branch == "master") };

// Capabilities the agent may use freely
permit (principal, action in [Interlock::Action::"shell.build_or_test", Interlock::Action::"fs.write", Interlock::Action::"install"], resource);

// Network: only these hosts, whether the agent uses a fetch tool or curl in a shell
permit (principal, action == Interlock::Action::"net.egress", resource)
when { ["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"].containsAll(context.input.hosts) };

// Capabilities always denied
forbid (principal, action == Interlock::Action::"sys.privilege", resource);
