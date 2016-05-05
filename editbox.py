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

import volatility.debug as debug
import volatility.obj as obj
import volatility.utils as utils

import volatility.plugins.common as common
import volatility.plugins.gui.messagehooks as messagehooks
import volatility.win32 as win32


supported_controls = {
    'edit': 'COMCTL_EDIT',
}

#---------------------------------------------------------------------
# Edit
#---------------------------------------------------------------------
editbox_vtypes_xp_x86 = {
    'COMCTL_EDIT': [ 0xEE, {
        'hBuf': [ 0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [ 0x38, ['unsigned long']],
        'parenthWnd': [ 0x58, ['unsigned long']],
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
    'COMCTL_EDIT': [ 0xF6, {
        'hBuf': [ 0x00, ['pointer', ['pointer', ['unsigned long']]]],
        'hWnd': [ 0x38, ['unsigned long']],
        'parenthWnd': [ 0x58, ['unsigned long']],
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
    'COMCTL_EDIT': [ 0x142, {
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
        
        return '<COMCTL_EDIT(Text={0}, Len={1}, Pwd={2}, Undo={3}, UndoLen={4})>'.format(
            text, self.nChars, self.is_pwd(), undo, self.undoLen)
    
    def get_text(self):
        if self.nChars < 1:
            return ''
        text_deref = obj.Object('address', offset=self.hBuf, vm=self.obj_vm)
        bytes = self.obj_vm.read(text_deref, self.nChars * 2)
        if not self.pwdChar == 0x00:  # Is a password dialog
            bytes = COMCTL_EDIT.RtlRunDecodeUnicodeString(self.bEncKey, bytes)
        return bytes.decode('utf-16')
    
    def get_undo(self):
        if self.undoLen < 1:
            return ''
        return self.obj_vm.read(self.undoBuf, self.undoLen * 2).decode('utf-16')
    
    def is_pwd(self):
        return self.pwdChar != 0x00
    
    @staticmethod
    def RtlRunDecodeUnicodeString(key, data):
        s = ''.join([chr(ord(data[i-1]) ^ ord(data[i]) ^ key) for i in range(1,len(data))])
        s = chr(ord(data[0]) ^ (key | 0x43)) + s
        return s


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
        config.add_option('PID', short_option = 'p', default = None,
            help = 'Operate on these Process IDs (comma-separated)',
            action = 'store', type = 'str')
    
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
        """Parse the control structure"""
        
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
                        
                        atom_class = mh.translate_atom(winsta,
                            atom_tables, wnd.ClassAtom)
                        
                        if atom_class:
                            atom_class = str(atom_class)
                            if '!' in atom_class:
                                comctl_class = atom_class.split('!')[-1].lower()
                                if comctl_class in supported_controls:
                                    task_vm = wnd.Process.get_process_address_space()                                
                                    wndextra_offset = wnd.v() + addr_space.profile.get_obj_size('tagWND')
                                    wndextra = obj.Object('address', offset=wndextra_offset, vm=task_vm)
                                    ctrl = obj.Object(supported_controls[comctl_class], offset=wndextra, vm=task_vm)
                                    yield wnd.Process.UniqueProcessId, wnd.Process.ImageFileName, ctrl
    
    def render_text(self, outfd, data):
        """Output the results as text
        
        @param  outfd: <file>
        @param  data: <generator>
        """
        
        self.table_header(outfd, [
            ('PID', '6'),
            ('Process', '14'),
            ('Control', ""),
            ])
        
        for pid, proc_name, edit in data:
            self.table_row(outfd, pid, proc_name, str(edit))
