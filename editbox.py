# Volatility EditBox plugin
#
# Author: Bridgey the Geek <bridgeythegeek@gmail.com>
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PRACTICAL PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this plugin. If not, see <http://www.gnu.org/licenses/>.
#
# This work heavily inspired by GDI Utilities from Dr Brendan Dolan-Gavitt PhD.
# <http://www.cc.gatech.edu/~brendan/volatility/>
#
# The iteration of the Windows objects is borrowed from the Windows plugin.
# <https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/gui/windows.py>
#
# This plugin wouldn't exist without the assistance of those on the volusers
# mailing list <http://lists.volatilesystems.com/mailman/listinfo/vol-users>.

"""
@author     : Bridgey the Geek
@license    : GPL 2 or later
@contact    : bridgeythegeek@gmail.com
"""

import os

import volatility.debug as debug
import volatility.obj as obj
import volatility.utils as utils

import volatility.plugins.common as common
import volatility.plugins.gui.messagehooks as messagehooks
import volatility.win32 as win32

supported_controls = {
    'edit': 'COMCTL_EDIT',
}

# ---------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------
editbox_vtypes_xp_x86 = {
    'COMCTL_EDIT': [0xEE, {
        'hBuf': [0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [0x38, ['unsigned long']],
        'parenthWnd': [0x58, ['unsigned long']],
        'nChars': [0x0C, ['unsigned long']],
        'selStart': [0x14, ['unsigned long']],
        'selEnd': [0x18, ['unsigned long']],
        'pwdChar': [0x30, ['unsigned short']],
        'undoBuf': [0x80, ['unsigned long']],
        'undoPos': [0x84, ['long']],
        'undoLen': [0x88, ['long']],
        'bEncKey': [0xEC, ['unsigned char']],
    }]
}

editbox_vtypes_xp_x64 = {
}

editbox_vtypes_vista7_x86 = {
    'COMCTL_EDIT': [0xF6, {
        'hBuf': [0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [0x38, ['unsigned long']],
        'parenthWnd': [0x58, ['unsigned long']],
        'nChars': [0x0C, ['unsigned long']],
        'selStart': [0x14, ['unsigned long']],
        'selEnd': [0x18, ['unsigned long']],
        'pwdChar': [0x30, ['unsigned short']],
        'undoBuf': [0x88, ['unsigned long']],
        'undoPos': [0x8C, ['long']],
        'undoLen': [0x90, ['long']],
        'bEncKey': [0xF4, ['unsigned char']],
    }]
}

editbox_vtypes_vista7_x64 = {
    'COMCTL_EDIT': [0x142, {
        'hBuf': [0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [0x40, ['unsigned long']],
        'parenthWnd': [0x60, ['unsigned long']],
        'nChars': [0x10, ['unsigned long']],
        'selStart': [0x18, ['unsigned long']],
        'selEnd': [0x20, ['unsigned long']],
        'pwdChar': [0x34, ['unsigned short']],
        'undoBuf': [0xA8, ['unsigned long']],
        'undoPos': [0xB0, ['long']],
        'undoLen': [0xB4, ['long']],
        'bEncKey': [0x140, ['unsigned char']],
    }]
}


class COMCTL_EDIT(obj.CType):
    """Methods for the Edit structure"""

    def __str__(self):
        """String representation of the Edit"""

        _MAX_OUT = 50

        text = self.get_text()
        text = '{}...'.format(text[:_MAX_OUT - 3]) if len(text) > _MAX_OUT else text

        undo = self.get_undo()
        undo = '{}...'.format(undo[:_MAX_OUT - 3]) if len(undo) > _MAX_OUT else undo

        return \
            '<COMCTL_EDIT(Text={0}, Len={1}, Pwd={2}, Undo={3}, UndoLen={4})>'.format(
                text, self.nChars, self.is_pwd(), undo, self.undoLen)

    def get_text(self):
        if self.nChars < 1:
            return ''
        text_deref = obj.Object('address', offset=self.hBuf, vm=self.obj_vm)
        raw = self.obj_vm.read(text_deref, self.nChars * 2)
        if not self.pwdChar == 0x00:  # Is a password dialog
            raw = COMCTL_EDIT.rtl_run_decode_unicode_string(self.bEncKey, raw)
        return raw.decode('utf-16')

    def get_undo(self):
        if self.undoLen < 1:
            return ''
        return self.obj_vm.read(self.undoBuf, self.undoLen * 2).decode('utf-16')

    def is_pwd(self):
        return self.pwdChar != 0x00

    def dump_meta(self, outfd):
        """Dumps the meta data of the control
        
        @param  outfd: 
        """
        outfd.write('nChars            : {}\n'.format(self.nChars))
        outfd.write('selStart          : {}\n'.format(self.selStart))
        outfd.write('selEnd            : {}\n'.format(self.selEnd))
        outfd.write('isPwdControl      : {}\n'.format(self.is_pwd()))
        outfd.write('undoPos           : {}\n'.format(self.undoPos))
        outfd.write('undoLen           : {}\n'.format(self.undoLen))
        outfd.write('address-of undoBuf: {:#x}\n'.format(self.undoBuf))
        outfd.write('undoBuf           : {}\n'.format(self.get_undo()))

    def dump_data(self, outfd):
        """Dumps the data of the control
        
        @param  outfd: 
        """
        outfd.write('{}\n'.format(self.get_text()))

    @staticmethod
    def rtl_run_decode_unicode_string(key, data):
        s = ''.join([chr(ord(data[i - 1]) ^ ord(data[i]) ^ key) for i in range(1, len(data))])
        s = chr(ord(data[0]) ^ (key | 0x43)) + s
        return s


def dump_to_file(ctrl, pid, proc_name, folder):
    """Dumps the data of the control to a file

    @param  ctrl:
    @param  pid:
    @param  proc_name:
    """
    ctrl_safe_name = str(ctrl.__class__.__name__).split('_')[-1].lower()
    file_name = '{0}_{1}_{2}_{3:#x}.txt'.format(pid, proc_name, ctrl_safe_name, ctrl.v())
    with open(os.path.join(folder, file_name), 'wb') as out_file:
        out_file.write(ctrl.get_text())


class Editbox2(common.AbstractWindowsCommand):
    """Displays information about Edit controls. (Listbox experimental.)"""

    # Add the classes for the structures
    editbox_classes = {
        'COMCTL_EDIT': COMCTL_EDIT,
    }

    # Map the version of Windows to the correct vtypes
    version_map = {
        'windows': {
            5: {
                '32bit': editbox_vtypes_xp_x86,
                '64bit': editbox_vtypes_xp_x64,
            },
            6: {
                '32bit': editbox_vtypes_vista7_x86,
                '64bit': editbox_vtypes_vista7_x64,
            },
        }
    }

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        # Filter specific processes
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')
        config.add_option('DUMP-DIR', short_option='D', default=None,
                          help='Save the found text to files in this folder',
                          action='store', type='str')

    @staticmethod
    def apply_types(addr_space):
        """Add the correct vtypes and classes for the profile
        
        @param  addr_space: <volatility.BaseAddressSpace>
        """

        meta = addr_space.profile.metadata
        try:
            vtypes = Editbox2.version_map[
                meta['os']][meta['major']][meta['memory_model']]
            addr_space.profile.vtypes.update(vtypes)
            addr_space.profile.object_classes.update(Editbox2.editbox_classes)
            addr_space.profile.compile()

        except KeyError:
            debug.error("The selected address space is not supported")

    def calculate(self):
        """Parse the control structures"""

        # Check the output folder exists
        if self._config.DUMP_DIR and not os.path.isdir(self._config.dump_dir):
            debug.error('{0} is not a directory'.format(self._config.dump_dir))

        # Apply the correct vtypes for the profile
        addr_space = utils.load_as(self._config)
        self.apply_types(addr_space)

        # Build a list of tasks
        tasks = win32.tasks.pslist(addr_space)
        if self._config.PID:
            pids = [int(p) for p in self._config.PID.split(',')]
            the_tasks = [t for t in tasks if t.UniqueProcessId in pids]
        else:
            the_tasks = [t for t in tasks]

        # In case no PIDs found
        if len(the_tasks) < 1:
            return

        # Iterate through all the window objects matching for supported controls
        mh = messagehooks.MessageHooks(self._config)
        for winsta, atom_tables in mh.calculate():
            for desktop in winsta.desktops():
                for wnd, _level in desktop.windows(desktop.DeskInfo.spwnd):
                    if wnd.Process in the_tasks:

                        atom_class = mh.translate_atom(winsta, atom_tables, wnd.ClassAtom)
                        if atom_class:
                            atom_class = str(atom_class)
                            if '!' in atom_class:
                                comctl_class = atom_class.split('!')[-1].lower()
                                if comctl_class in supported_controls:
                                    context = '{0}\\{1}\\{2}'.format(winsta.dwSessionId, winsta.Name, desktop.Name)
                                    task_vm = wnd.Process.get_process_address_space()
                                    wndextra_offset = wnd.v() + addr_space.profile.get_obj_size('tagWND')
                                    wndextra = obj.Object('address', offset=wndextra_offset, vm=task_vm)
                                    ctrl = obj.Object(supported_controls[comctl_class], offset=wndextra, vm=task_vm)
                                    if self._config.DUMP_DIR:
                                        dump_to_file(ctrl, wnd.Process.UniqueProcessId,
                                                     wnd.Process.ImageFileName, self._config.DUMP_DIR)
                                    yield context, atom_class, wnd.Process.UniqueProcessId, \
                                        wnd.Process.ImageFileName, ctrl

    def render_table(self, outfd, data):
        """Output the results as a table
        
        @param  outfd: <file>
        @param  data: <generator>
        """

        self.table_header(outfd, [
            ('PID', '6'),
            ('Process', '14'),
            ('Control', ""),
        ])

        for context, atom_class, pid, proc_name, ctrl in data:
            # context and atom_class are ignored
            self.table_row(outfd, pid, proc_name, str(ctrl))

    def render_text(self, outfd, data):
        """Output the results as a text report
        
        @param  outfd: <file>
        @param  data: <generator>
        """

        for context, atom_class, pid, proc_name, ctrl in data:
            outfd.write('{}\n'.format('*' * 30))
            outfd.write('Wnd Context       : {}\n'.format(context))
            outfd.write('Process ID        : {}\n'.format(pid))
            outfd.write('ImageFileName     : {}\n'.format(proc_name))
            outfd.write('atom_class        : {}\n'.format(atom_class))
            outfd.write('value-of WndExtra : {:#x}\n'.format(ctrl.v()))
            ctrl.dump_meta(outfd)
            outfd.write('{}\n'.format('-' * 25))
            ctrl.dump_data(outfd)
