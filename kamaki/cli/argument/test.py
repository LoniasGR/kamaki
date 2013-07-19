# Copyright 2013 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

from mock import patch, call, MagicMock
from unittest import TestCase
from StringIO import StringIO
from datetime import datetime
#from itertools import product

from kamaki.cli import argument, errors
from kamaki.cli.config import Config


def assert_dicts_are_equal(test_case, d1, d2):
    for k, v in d1.items():
        test_case.assertTrue(k in d2)
        if isinstance(v, dict):
            test_case.assert_dicts_are_equal(v, d2[k])
        else:
            test_case.assertEqual(unicode(v), unicode(d2[k]))


cnf_path = 'kamaki.cli.config.Config'


class Argument(TestCase):

    def test___init__(self):
        self.assertRaises(ValueError, argument.Argument, 'non-integer')
        self.assertRaises(AssertionError, argument.Argument, 1)
        self.assertRaises(AssertionError, argument.Argument, 0, 'noname')
        self.assertRaises(AssertionError, argument.Argument, 0, '--no name')
        self.assertRaises(AssertionError, argument.Argument, 0, ['-n', 'n m'])
        for arity, help, parsed_name, default in (
                (0, 'help 0', '--zero', None),
                (1, 'help 1', ['--one', '-o'], 'lala'),
                (-1, 'help -1', ['--help', '--or', '--more'], 0),
                (0, 'help 0 again', ['--again', ], True)):
            a = argument.Argument(arity, help, parsed_name, default)
            if arity:
                self.assertEqual(arity, a.arity)
            self.assertEqual(help, a.help)

            exp_name = parsed_name if (
                isinstance(parsed_name, list)) else [parsed_name, ]
            self.assertEqual(exp_name, a.parsed_name)

            exp_default = default or (None if arity else False)
            self.assertEqual(exp_default, a.default)

    def test_value(self):
        a = argument.Argument(1, parsed_name='--value')
        for value in (None, '', 0, 0.1, -12, [1, 'a', 2.8], (3, 'lala'), 'pi'):
            a.value = value
            self.assertEqual(value, a.value)

    def test_update_parser(self):
        for i, arity in enumerate((-1, 0, 1)):
            arp = argument.ArgumentParser()
            pname, aname = '--pname%s' % i, 'a_name_%s' % i
            a = argument.Argument(arity, 'args', pname, 42)
            a.update_parser(arp, aname)

            f = StringIO()
            arp.print_usage(file=f), f.seek(0)
            usage, exp = f.readline(), '[%s%s]\n' % (
                pname, (' %s' % aname.upper()) if arity else '')
            self.assertEqual(usage[-len(exp):], exp)
            del arp


class ConfigArgument(TestCase):

    def setUp(self):
        argument._config_arg = argument.ConfigArgument('Recovered Path')

    def test_value(self):
        c = argument._config_arg
        self.assertEqual(c.value, None)
        exp = '/some/random/path'
        c.value = exp
        self.assertTrue(isinstance(c.value, Config))
        self.assertEqual(c.file_path, exp)
        self.assertEqual(c.value.path, exp)

    def test_get(self):
        c = argument._config_arg
        c.value = None
        with patch('%s.get' % cnf_path, return_value='config') as get:
            self.assertEqual(c.value.get('global', 'config_cli'), 'config')
            self.assertEqual(get.mock_calls[-1], call('global', 'config_cli'))

    @patch('%s.keys' % cnf_path, return_value=(
        'image_cli', 'config_cli', 'history_cli', 'file'))
    def test_groups(self, keys):
        c = argument._config_arg
        c.value = None
        cset = set(c.groups)
        self.assertTrue(cset.issuperset(['image', 'config', 'history']))
        self.assertEqual(keys.mock_calls[-1], call('global'))
        self.assertFalse('file' in cset)
        self.assertEqual(keys.mock_calls[-1], call('global'))

    @patch('%s.items' % cnf_path, return_value=(
        ('image_cli', 'image'), ('file', 'pithos'),
        ('config_cli', 'config'), ('history_cli', 'history')))
    def test_cli_specs(self, items):
        c = argument._config_arg
        c.value = None
        cset = set(c.cli_specs)
        self.assertTrue(cset.issuperset([
            ('image', 'image'), ('config', 'config'), ('history', 'history')]))
        self.assertEqual(items.mock_calls[-1], call('global'))
        self.assertFalse(cset.issuperset([('file', 'pithos'), ]))
        self.assertEqual(items.mock_calls[-1], call('global'))

    def test_get_global(self):
        c = argument._config_arg
        c.value = None
        for k, v in (
                ('config_cli', 'config'),
                ('image_cli', 'image'),
                ('history_cli', 'history')):
            with patch('%s.get_global' % cnf_path, return_value=v) as gg:
                self.assertEqual(c.get_global(k), v)
                self.assertEqual(gg.mock_calls[-1], call(k))

    def test_get_cloud(self):
        c = argument._config_arg
        c.value = None
        with patch(
                '%s.get_cloud' % cnf_path,
                return_value='http://cloud') as get_cloud:
            self.assertTrue(len(c.get_cloud('mycloud', 'url')) > 0)
            self.assertEqual(get_cloud.mock_calls[-1],  call('mycloud', 'url'))
        with patch(
                '%s.get_cloud' % cnf_path,
                side_effect=KeyError('no token')) as get_cloud:
            self.assertRaises(KeyError, c.get_cloud, 'mycloud', 'token')
        invalidcloud = 'PLEASE_DO_NOT_EVER_NAME_YOUR_CLOUD_LIKE_THIS111'
        self.assertRaises(KeyError, c.get_cloud, invalidcloud, 'url')


class RuntimeConfigArgument(TestCase):

    def setUp(self):
        argument._config_arg = argument.ConfigArgument('Recovered Path')

    @patch('kamaki.cli.argument.Argument.__init__')
    def test___init__(self, arg):
        config, help, pname, default = 'config', 'help', 'pname', 'default'
        rca = argument.RuntimeConfigArgument(config, help, pname, default)
        self.assertTrue(isinstance(rca, argument.RuntimeConfigArgument))
        self.assertEqual(rca._config_arg, config)
        self.assertEqual(arg.mock_calls[-1], call(1, help, pname, default))

    @patch('%s.override' % cnf_path)
    def test_value(self, override):
        config, help, pname, default = argument._config_arg, 'help', '-n', 'df'
        config.value = None
        rca = argument.RuntimeConfigArgument(config, help, pname, default)
        self.assertEqual(rca.value, default)

        for options in ('grp', 'grp.opt', 'k v', '=nokey', 2.8, None, 42, ''):
            self.assertRaises(TypeError, rca.value, options)

        for options in ('key=val', 'grp.key=val', 'dotted.opt.key=val'):
            rca.value = options
            option, sep, val = options.partition('=')
            grp, sep, key = option.partition('.')
            grp, key = (grp, key) if key else ('global', grp)
            self.assertEqual(override.mock_calls[-1], call(grp, key, val))


class FlagArgument(TestCase):

    @patch('kamaki.cli.argument.Argument.__init__')
    def test___init__(self, arg):
        help, pname, default = 'help', 'pname', 'default'
        fa = argument.FlagArgument(help, pname, default)
        self.assertTrue(isinstance(fa, argument.FlagArgument))
        arg.assert_called_once(0, help, pname, default)


class ValueArgument(TestCase):

    @patch('kamaki.cli.argument.Argument.__init__')
    def test___init__(self, arg):
        help, pname, default = 'help', 'pname', 'default'
        fa = argument.ValueArgument(help, pname, default)
        self.assertTrue(isinstance(fa, argument.ValueArgument))
        arg.assert_called_once(1, help, pname, default)


class IntArgument(TestCase):

    def test_value(self):
        ia = argument.IntArgument(parsed_name='--ia')
        self.assertEqual(ia.value, None)
        for v in (1, 0, -1, 923455555555555555555555555555555):
            ia.value = v
            self.assertEqual(ia.value, v)
        for v in ('1', '-1', 2.8):
            ia.value = v
            self.assertEqual(ia.value, int(v))
        for v, err in (
                ('invalid', errors.CLIError),
                (None, TypeError), (False, TypeError), ([1, 2, 3], TypeError)):
            try:
                ia.value = v
            except Exception as e:
                self.assertTrue(isinstance(e, err))


class DateArgument(TestCase):

    def test_timestamp(self):
        da = argument.DateArgument(parsed_name='--date')
        self.assertEqual(da.timestamp, None)
        date, format, exp = '24-10-1917', '%d-%m-%Y', -1646964000.0
        da._value = argument.dtm.strptime(date, format)
        self.assertEqual(da.timestamp, exp)

    def test_formated(self):
        da = argument.DateArgument(parsed_name='--date')
        self.assertEqual(da.formated, None)
        date, format, exp = (
            '24-10-1917', '%d-%m-%Y', 'Wed Oct 24 00:00:00 1917')
        da._value = argument.dtm.strptime(date, format)
        self.assertEqual(da.formated, exp)

    @patch('kamaki.cli.argument.DateArgument.timestamp')
    @patch('kamaki.cli.argument.DateArgument.format_date')
    def test_value(self, format_date, timestamp):
        da = argument.DateArgument(parsed_name='--date')
        self.assertTrue(isinstance(da.value, MagicMock))
        da.value = 'Something'
        format_date.assert_called_once(call('Something'))

    def test_format_date(self):
        da = argument.DateArgument(parsed_name='--date')
        for datestr, exp in (
                ('Wed Oct 24 01:02:03 1917', datetime(1917, 10, 24, 1, 2, 3)),
                ('24-10-1917', datetime(1917, 10, 24)),
                ('01:02:03 24-10-1917', datetime(1917, 10, 24, 1, 2, 3))):
            self.assertEqual(da.format_date(datestr), exp)
        for datestr, err in (
                ('32-40-20134', errors.CLIError),
                ('Wednesday, 24 Oct 2017', errors.CLIError),
                (None, TypeError), (0.8, TypeError)):
            self.assertRaises(err, da.format_date, datestr)


class VersionArgument(TestCase):

    def test_value(self):
        va = argument.VersionArgument(parsed_name='--version')
        self.assertTrue(va, argument.VersionArgument)
        va.value = 'some value'
        self.assertEqual(va.value, 'some value')


class KeyValueArgument(TestCase):

    @patch('kamaki.cli.argument.Argument.__init__')
    def test___init__(self, init):
        help, pname, default = 'help', 'pname', 'default'
        kva = argument.KeyValueArgument(help, pname, default)
        self.assertTrue(isinstance(kva, argument.KeyValueArgument))
        self.assertEqual(init.mock_calls[-1], call(-1, help, pname, default))

    def test_value(self):
        kva = argument.KeyValueArgument(parsed_name='--keyval')
        self.assertEqual(kva.value, None)
        for kvpairs in (
                'strval', 'key=val', 2.8, 42, None,
                ('key', 'val'), ('key val'), ['=val', 'key=val'],
                ['key1=val1', 'key2 val2'], ('key1 = val1', )):
            self.assertRaises(errors.CLIError, kva.value, kvpairs)
        for kvpairs, exp in (
                (('key=val', ), {'key': 'val'}),
                (['key1=val1', 'key2=val2'], {'key1': 'val1', 'key2': 'val2'}),
                (
                    ('k1=v1 v2', 'k3=', 'k 4=v4'),
                    {'k1': 'v1 v2', 'k3': '', 'k 4': 'v4'}),
                (('k=v1', 'k=v2', 'k=v3'), {'k': 'v3'})
            ):
            kva.value = kvpairs
            assert_dicts_are_equal(self, kva.value, exp)


class ProgressBarArgument(TestCase):

    class PseudoBar(object):
            message = ''
            suffix = ''

            def start():
                pass

    @patch('kamaki.cli.argument.FlagArgument.__init__')
    def test___init__(self, init):
        help, pname, default = 'help', '--progress', 'default'
        pba = argument.ProgressBarArgument(help, pname, default)
        self.assertTrue(isinstance(pba, argument.ProgressBarArgument))
        self.assertEqual(pba.suffix, '%(percent)d%%')
        init.assert_called_once(help, pname, default)

    def test_clone(self):
        pba = argument.ProgressBarArgument(parsed_name='--progress')
        pba.value = None
        pba_clone = pba.clone()
        self.assertTrue(isinstance(pba, argument.ProgressBarArgument))
        self.assertTrue(isinstance(pba_clone, argument.ProgressBarArgument))
        self.assertNotEqual(pba, pba_clone)
        self.assertEqual(pba.parsed_name, pba_clone.parsed_name)

    def test_get_generator(self):
        pba = argument.ProgressBarArgument(parsed_name='--progress')
        pba.value = None
        msg, msg_len = 'message', 40
        with patch('kamaki.cli.argument.KamakiProgressBar.start') as start:
            pba.get_generator(msg, msg_len)
            self.assertTrue(isinstance(pba.bar, argument.KamakiProgressBar))
            self.assertNotEqual(pba.bar.message, msg)
            self.assertEqual(
                pba.bar.message, '%s%s' % (msg, ' ' * (msg_len - len(msg))))
            self.assertEqual(pba.bar.suffix, '%(percent)d%% - %(eta)ds')
            start.assert_called_once()

    def test_finish(self):
        pba = argument.ProgressBarArgument(parsed_name='--progress')
        pba.value = None
        self.assertEqual(pba.finish(), None)
        pba.bar = argument.KamakiProgressBar()
        with patch('kamaki.cli.argument.KamakiProgressBar.finish') as finish:
            pba.finish()
            finish.assert_called_once()


class ArgumentParseManager(TestCase):

    @patch('kamaki.cli.argument.ArgumentParseManager.parse')
    @patch('kamaki.cli.argument.ArgumentParseManager.update_parser')
    def test___init__(self, parse, update_parser):
        for arguments in (None, {'k1': 'v1', 'k2': 'v2'}):
            apm = argument.ArgumentParseManager('exe', arguments)
            self.assertTrue(isinstance(apm, argument.ArgumentParseManager))

            self.assertTrue(isinstance(apm.parser, argument.ArgumentParser))
            self.assertFalse(apm.parser.add_help)
            self.assertEqual(
                apm.parser.formatter_class,
                argument.RawDescriptionHelpFormatter)

            self.assertEqual(
                apm.syntax, 'exe <cmd_group> [<cmd_subbroup> ...] <cmd>')
            assert_dicts_are_equal(
                self, apm.arguments,
                arguments or argument._arguments)
            self.assertFalse(apm._parser_modified)
            self.assertEqual(apm._parsed, None)
            self.assertEqual(apm._unparsed, None)
            self.assertEqual(parse.mock_calls[-1], call())
            if arguments:
                update_parser.assert_called_once()

    def test_syntax(self):
        apm = argument.ArgumentParseManager('exe')
        self.assertEqual(
            apm.syntax, 'exe <cmd_group> [<cmd_subbroup> ...] <cmd>')
        apm.syntax = 'some syntax'
        self.assertEqual(apm.syntax, 'some syntax')

    @patch('kamaki.cli.argument.ArgumentParseManager.update_parser')
    def test_arguments(self, update_parser):
        apm = argument.ArgumentParseManager('exe')
        assert_dicts_are_equal(self, apm.arguments, argument._arguments)
        update_parser.assert_called_once()
        exp = {'k1': 'v1', 'k2': 'v2'}
        apm.arguments = exp
        assert_dicts_are_equal(self, apm.arguments, exp)
        self.assertEqual(update_parser.mock_calls[-1], call())
        try:
            apm.arguments = None
        except Exception as e:
            self.assertTrue(isinstance(e, AssertionError))

    @patch('kamaki.cli.argument.ArgumentParseManager.parse')
    def test_parsed(self, parse):
        apm = argument.ArgumentParseManager('exe')
        self.assertEqual(apm.parsed, None)
        exp = 'you have been parsed'
        apm._parsed = exp
        self.assertEqual(apm.parsed, exp)
        apm._parser_modified = True
        apm._parsed = exp + ' v2'
        self.assertEqual(apm.parsed, exp + ' v2')
        self.assertEqual(parse.mock_calls, [call(), call()])

    @patch('kamaki.cli.argument.ArgumentParseManager.parse')
    def test_unparsed(self, parse):
        apm = argument.ArgumentParseManager('exe')
        self.assertEqual(apm.unparsed, None)
        exp = 'you have been unparsed'
        apm._unparsed = exp
        self.assertEqual(apm.unparsed, exp)
        apm._parser_modified = True
        apm._unparsed = exp + ' v2'
        self.assertEqual(apm.unparsed, exp + ' v2')
        self.assertEqual(parse.mock_calls, [call(), call()])

    @patch('kamaki.cli.argument.Argument.update_parser')
    def test_update_parser(self, update_parser):
        apm = argument.ArgumentParseManager('exe')
        body_count = len(update_parser.mock_calls)
        exp = len(argument._arguments)
        self.assertEqual(body_count, exp)
        apm.update_parser()
        exp = len(apm.arguments) + body_count
        body_count = len(update_parser.mock_calls)
        self.assertEqual(body_count, exp)
        expd = dict(
            k1=argument.Argument(0, parsed_name='-a'),
            k2=argument.Argument(0, parsed_name='-b'))
        apm.update_parser(expd)
        body_count = len(update_parser.mock_calls)
        self.assertEqual(body_count, exp + 2)

if __name__ == '__main__':
    from sys import argv
    from kamaki.cli.test import runTestCase
    runTestCase(Argument, 'Argument', argv[1:])
    runTestCase(ConfigArgument, 'ConfigArgument', argv[1:])
    runTestCase(RuntimeConfigArgument, 'RuntimeConfigArgument', argv[1:])
    runTestCase(FlagArgument, 'FlagArgument', argv[1:])
    runTestCase(FlagArgument, 'ValueArgument', argv[1:])
    runTestCase(IntArgument, 'IntArgument', argv[1:])
    runTestCase(DateArgument, 'DateArgument', argv[1:])
    runTestCase(VersionArgument, 'VersionArgument', argv[1:])
    runTestCase(KeyValueArgument, 'KeyValueArgument', argv[1:])
    runTestCase(ProgressBarArgument, 'ProgressBarArgument', argv[1:])
    runTestCase(ArgumentParseManager, 'ArgumentParseManager', argv[1:])
