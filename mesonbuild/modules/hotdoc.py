import os
import sys
import subprocess
from pathlib import Path

from mesonbuild import mesonlib
from mesonbuild import mlog, build
from mesonbuild.coredata import MesonException
from . import ModuleReturnValue
from . import ExtensionModule
from . import get_include_args
from ..dependencies import Dependency, InternalDependency, ExternalProgram


def ensure_list(value):
    if not isinstance(value, list):
        return [value]
    return value


NO_VALUE = "__no value at all__"
MIN_HOTDOC_VERSION = '0.8.100'


class HotdocTargetBuilder:
    def __init__(self, name, state, hotdoc, kwargs):
        self.hotdoc = hotdoc
        self.build_by_default = kwargs.pop('build_by_default', False)
        self.kwargs = kwargs
        self.name = name
        self.state = state

        self.builddir = state.environment.get_build_dir()
        self.sourcedir = state.environment.get_source_dir()
        self.subdir = state.subdir
        self.build_command = state.environment.get_build_command()

        self.cmd = ['conf', '--project-name', name, "--disable-incremental-build",
                    '--output', os.path.join(self.builddir, self.subdir, self.name + '-doc')]
        self._extra_extension_paths = set()

        self._dependencies = []
        self._subprojects = []

    def add_arg(self, option, types, argname=None, default=NO_VALUE,
                value_processor=None, mandatory=False, force_list=False,
                local_default=NO_VALUE, keep_processed=False):
        if not argname:
            argname = option.strip("-").replace("-", "_")

        value, unprocessed_value = self.get_value(
            types, argname, default, value_processor, mandatory, force_list)

        self.set_value(option, argname, value, unprocessed_value,
                       local_default, keep_processed=keep_processed)

        return self

    def set_value(self, option, argname, value, unprocessed_value=None, default=NO_VALUE,
                  keep_processed=False):
        if value != NO_VALUE:
            if isinstance(value, bool):
                self.cmd.append(option)
            elif isinstance(value, list):
                # Do not do anything on empty lists
                if value:
                    if option:
                        self.cmd.extend([option] + value)
                    else:
                        self.cmd.extend(value)
            else:
                self.cmd.extend([option, value])
        elif default != NO_VALUE:
            value = default
        else:
            return

        if keep_processed:
            setattr(self, argname, value)
        else:
            setattr(self, argname, unprocessed_value)

    def process_extra_args(self):
        for arg, value in self.kwargs.items():
            option = "--" + arg.replace("_", "-")
            self.set_value(option, arg, value)

    def get_value(self, types, argname, default=NO_VALUE, value_processor=None,
                  mandatory=False, force_list=False):
        if not isinstance(types, list):
            types = [types]
        try:
            uvalue = value = self.kwargs.pop(argname)
            if value_processor:
                value = value_processor(value)

            for t in types:
                if isinstance(value, t):
                    if force_list and not isinstance(value, list):
                        return [value], uvalue
                    return value, uvalue
            raise MesonException("%s field value %s is not valid,"
                                 " valid types are %s" % (argname, value,
                                                          types))
        except KeyError:
            if mandatory:
                raise MesonException("%s mandatory field not found" % argname)

            if default != NO_VALUE:
                return default, default

        return NO_VALUE, NO_VALUE

    def setup_extension_paths(self, paths):
        if not isinstance(paths, list):
            paths = [paths]

        for path in paths:
            try:
                self.add_extension_paths([path])
            except subprocess.CalledProcessError as e:
                raise MesonException(
                    "Could not setup hotdoc extension %s: %s" % (paths, e))

        return []

    def add_extension_paths(self, paths):
        for path in paths:
            if path in self._extra_extension_paths:
                continue

            self._extra_extension_paths.add(path)
            self.cmd.extend(["--extra-extension-path", path])

    def process_extra_extension_paths(self):
        self.get_value([list, str], 'extra_extensions_paths',
                       default="", value_processor=self.setup_extension_paths)
        return self

    def replace_dirs_in_string(self, string):
        return string.replace("@SOURCE_ROOT@", self.sourcedir).replace("@BUILD_ROOT@", self.builddir)

    def process_dependencies(self, deps):
        cflags = set()
        for dep in mesonlib.listify(ensure_list(deps)):
            dep = getattr(dep, "held_object", dep)
            if isinstance(dep, InternalDependency):
                inc_args = get_include_args(dep.include_directories)
                cflags.update([self.replace_dirs_in_string(x)
                               for x in inc_args])
                cflags.update(self.process_dependencies(dep.libraries))
                cflags.update(self.process_dependencies(dep.sources))
                cflags.update(self.process_dependencies(dep.ext_deps))
            elif isinstance(dep, Dependency):
                cflags.update(dep.get_compile_args())
            elif isinstance(dep, (build.StaticLibrary, build.SharedLibrary)):
                self._dependencies.append(dep)
                for incd in dep.get_include_dirs():
                    cflags.update(incd.get_incdirs())
            elif isinstance(dep, HotdocTarget):
                # Recurse in hotdoc target dependencies
                self.process_dependencies(dep.get_target_dependencies())
                self._subprojects.extend(dep.subprojects)
                self.process_dependencies(dep.subprojects)
                self.cmd += ['--include-paths',
                             os.path.join(self.builddir, dep.hotdoc_conf.subdir)]
                self.cmd += ['--extra-assets=' + p for p in dep.extra_assets]
                self.add_extension_paths(dep.extra_extension_paths)
            elif isinstance(dep, build.CustomTarget) or isinstance(dep, build.BuildTarget):
                self._dependencies.append(dep)

        return [f.strip('-I') for f in cflags]

    def process_subprojects(self):
        _, value = self.get_value([
            list, HotdocTarget], argname="subprojects",
            force_list=True, value_processor=self.process_dependencies)

        if value != NO_VALUE:
            self._subprojects.extend(value)

    def generate_hotdoc_config(self):
        cwd = os.path.abspath(os.curdir)
        ncwd = os.path.join(self.sourcedir, self.subdir)
        from hotdoc.run_hotdoc import run
        mlog.log('Generating Hotdoc configuration for: ', mlog.bold(self.name))
        os.chdir(ncwd)
        run(self.cmd)
        os.chdir(cwd)

    def finish(self):
        self.process_extra_extension_paths()
        self.process_subprojects()
        self.process_extra_args()

        install, install = self.get_value(bool, "install", mandatory=False)

        fullname = self.name + '-doc'
        hotdoc_config_name = fullname + '.json'
        hotdoc_config_path = os.path.join(
            self.builddir, self.subdir, hotdoc_config_name)
        with open(hotdoc_config_path, 'w') as f:
            f.write('{}')

        self.cmd += ['--conf-file', hotdoc_config_path]
        self.cmd += ['--include-paths',
                     os.path.join(self.builddir, self.subdir)]
        self.cmd += ['--include-paths',
                     os.path.join(self.sourcedir, self.subdir)]

        depfile = os.path.join(self.builddir, self.subdir, self.name + '.deps')
        self.cmd += ['--deps-file-dest', depfile]
        self.generate_hotdoc_config()

        target_cmd = self.build_command + ["--internal", "hotdoc"] + \
            self.hotdoc.get_command() + ['run', '--conf-file', hotdoc_config_name] + \
            ['--builddir', os.path.join(self.builddir, self.subdir)]

        res = [HotdocTarget(fullname,
                            subdir=self.subdir,
                            subproject=self.state.subproject,
                            hotdoc_conf=mesonlib.File.from_built_file(
                                self.subdir, hotdoc_config_name),
                            extra_extension_paths=self._extra_extension_paths,
                            extra_assets=self.extra_assets,
                            subprojects=self._subprojects,
                            command=target_cmd,
                            depends=self._dependencies,
                            output=fullname,
                            depfile=os.path.basename(depfile),
                            build_by_default=self.build_by_default)]

        if install == True:
            res.append(HotdocRunScript(self.build_command, [
                "--internal", "hotdoc",
                "--install", os.path.join(fullname, 'html'),
                '--name', self.name,
                '--builddir', os.path.join(self.builddir, self.subdir)] +
                self.hotdoc.get_command() +
                ['run', '--conf-file', hotdoc_config_name]))

        return res


class HotdocTarget(build.CustomTarget):
    def __init__(self, name, subdir, subproject, hotdoc_conf, extra_extension_paths, extra_assets,
                 subprojects, **kwargs):
        super().__init__(name, subdir, subproject, kwargs, absolute_paths=True)
        self.hotdoc_conf = hotdoc_conf
        self.extra_extension_paths = extra_extension_paths
        self.extra_assets = extra_assets
        self.subprojects = subprojects

    def __getstate__(self):
        # Make sure we do not try to pickle subprojects
        res = self.__dict__.copy()
        res['subprojects'] = []

        return res


class HotdocRunScript(build.RunScript):
    def __init__(self, script, args):
        super().__init__(script, args)


class HotDocModule(ExtensionModule):
    def __init__(self, interpreter):
        super().__init__(interpreter)
        self.hotdoc = ExternalProgram('hotdoc')
        if not self.hotdoc.found():
            raise MesonException('hotdoc executable not found')

        version = subprocess.check_output(self.hotdoc.command + ["--version"]).decode().strip('\n')
        if not mesonlib.version_compare(version, MIN_HOTDOC_VERSION):
            raise MesonException('hotdoc %s required, %s found' % (MIN_HOTDOC_VERSION, version))

    def generate_doc(self, state, args, kwargs):
        if len(args) != 1:
            raise MesonException('One positional argument is'
                                 ' required for the project name.')

        project_name = args[0]
        name = args[0]

        def file_to_path(value):
            if isinstance(value, mesonlib.File):
                return value.absolute_path(state.environment.get_source_dir(),
                                           state.environment.get_build_dir())
            return value

        def make_relative_path(value):
            if isinstance(value, list):
                res = []
                for val in value:
                    res.append(make_relative_path(val))
                return res

            if isinstance(value, mesonlib.File):
                return value.absolute_path(state.environment.get_source_dir(),
                                           state.environment.get_build_dir())

            if os.path.isabs(value):
                return value

            return os.path.relpath(os.path.join(state.environment.get_source_dir(), value),
                state.environment.get_build_dir())

        build_dir = os.path.join(
            state.environment.get_build_dir(), state.subdir)

        builder = HotdocTargetBuilder(project_name, state, self.hotdoc, kwargs)
        builder.add_arg("--sitemap", (str, mesonlib.File), mandatory=True, keep_processed=True,
                        value_processor=file_to_path)
        builder.add_arg("--html-extra-theme", (str, mesonlib.File), mandatory=False,
                        keep_processed=True, value_processor=make_relative_path)
        builder.add_arg("--include-paths", (str, mesonlib.File, list), mandatory=False,
                        keep_processed=True, value_processor=make_relative_path)
        builder.add_arg("--c-sources", (str, list),
                        local_default=[], keep_processed=True, force_list=True)
        builder.add_arg("--extra-assets", (str, list),
                        local_default=[], keep_processed=True, force_list=True)
        builder.add_arg(None, (str, list), "include_paths", force_list=True,
                        value_processor=lambda x: ["--include-paths=%s" % v for v in ensure_list(x)])
        builder.add_arg('--c-include-directories',
                        [Dependency, build.StaticLibrary,
                            build.SharedLibrary, list],
                        argname="dependencies", local_default=[],
                        force_list=True, value_processor=builder.process_dependencies)
        targets = builder.finish()

        return ModuleReturnValue(targets[0], targets)


def initialize(interpreter):
    return HotDocModule(interpreter)