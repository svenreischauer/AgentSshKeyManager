using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace AgentSshKeyManager
{
    internal static class EmbeddedDependencyLoader
    {
        private const string ResourcePrefix = "AgentSshKeyManager.Dependencies.";
        private static int _initialized;

        public static void Initialize()
        {
            if (Interlocked.Exchange(ref _initialized, 1) != 0) return;
            AppDomain.CurrentDomain.AssemblyResolve += ResolveEmbeddedAssembly;
        }

        private static Assembly ResolveEmbeddedAssembly(object sender, ResolveEventArgs args)
        {
            AssemblyName requested;
            try { requested = new AssemblyName(args.Name); }
            catch { return null; }

            Assembly existing = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(assembly =>
                string.Equals(assembly.GetName().Name, requested.Name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) return existing;

            string resourceName = ResourcePrefix + requested.Name + ".dll";
            Assembly executable = Assembly.GetExecutingAssembly();
            using (Stream stream = executable.GetManifestResourceStream(resourceName))
            {
                if (stream == null || stream.Length <= 0 || stream.Length > 32 * 1024 * 1024) return null;
                byte[] bytes = new byte[(int)stream.Length];
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int read = stream.Read(bytes, offset, bytes.Length - offset);
                    if (read <= 0) return null;
                    offset += read;
                }

                Assembly loaded = Assembly.Load(bytes);
                if (!string.Equals(loaded.GetName().Name, requested.Name, StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }
                return loaded;
            }
        }
    }
}
