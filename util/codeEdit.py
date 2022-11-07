#!/usr/bin/env jython
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__),"rsyntaxtextarea-3.2.0.jar"))
from org.fife.ui.rsyntaxtextarea import RSyntaxTextArea
from org.fife.ui.rsyntaxtextarea import SyntaxConstants

from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JScrollPane
from javax.swing import ScrollPaneConstants
from javax.swing import JMenuBar
from javax.swing import JMenu
from javax.swing import JMenuItem
from java.awt.event import KeyEvent
from javax.swing import JFileChooser
from java.io import File
from javax.swing import JTabbedPane


class CodePanel(JPanel):
	def __init__(self,path=None):
		self.setLayout( BoxLayout(self, BoxLayout.Y_AXIS) )

		self.codeArea = RSyntaxTextArea()
		if path != None and path[-5:].lower() == ".java":
			self.codeArea.setSyntaxEditingStyle(SyntaxConstants. SYNTAX_STYLE_JAVA)
		elif path != None and path[-4:].lower() in [".cpp",".c++",".hpp",".h++"]:
			self.codeArea.setSyntaxEditingStyle(SyntaxConstants. SYNTAX_STYLE_CPP)
		elif path != None and path[-2].lower() in [".c",".h"]:
			self.codeArea.setSyntaxEditingStyle(SyntaxConstants. SYNTAX_STYLE_C)
		else:
			self.codeArea.setSyntaxEditingStyle(SyntaxConstants. SYNTAX_STYLE_PYTHON)
		self.add( JScrollPane(self.codeArea, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS)	 )

		self.path = path
		if path != None:
				f = open(path,"r")
				self.codeArea.setText(f.read())
				f.close()
		
	def getPath(self):
		return self.path
		
	def save(self,path=None):
		if path == None:
			path = self.path
		else:
			self.path = path
		f = open(path,"w")
		f.write(self.codeArea.getText())
		f.close()
				
class CodeEditFrame(JFrame):
	def __init__(self, size=(740, 600)):
		JFrame.__init__(self, "codeEdit", defaultCloseOperation = JFrame.EXIT_ON_CLOSE, size=size)
		
		self.lastDir = None
		
		menuBar = JMenuBar()
		self.setJMenuBar(menuBar)
		
		fileMenu = JMenu("File")
		fileMenu.setMnemonic(KeyEvent.VK_F)
		fileMenu.add( JMenuItem("New",KeyEvent.VK_N,actionPerformed=self._new) )
		fileMenu.add( JMenuItem("Open",KeyEvent.VK_O,actionPerformed=self._open) )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Save",KeyEvent.VK_S,actionPerformed=self._save) )
		fileMenu.add( JMenuItem("Save As",KeyEvent.VK_A,actionPerformed=self._saveas) )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Close",KeyEvent.VK_C,actionPerformed=self._close) )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Exit",KeyEvent.VK_X,actionPerformed=self._exit) )
		menuBar.add(fileMenu)
		
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
		self.codePanels = JTabbedPane(JTabbedPane.TOP)
		self.add(self.codePanels)
	
	def _new(self,evt=None):
		self.new()
	
	def new(self):
		newPanel = CodePanel()
		self.codePanels.add( "new", newPanel )
	
	def _open(self,evt=None):
		dlg = JFileChooser()
		if self.lastDir != None:
			dlg.setCurrentDirectory(File(self.lastDir))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path =  dlg.getSelectedFile().getPath()
			self.open(path)
	
	def open(self,path):
		self.lastDir =  os.path.dirname(path)
		name = os.path.basename(path)
		newPanel = CodePanel(path)
		self.codePanels.add(  name, newPanel )
	
	def _save(self,evt=None):
		if self.codePanels.getSelectedComponent().getPath() == None:
			self._saveas(evt)
		else:
			self.save()
	
	def save(self):
		self.codePanels.getSelectedComponent().save()
	
	def _saveas(self,evt=None):
		dlg = JFileChooser()
		if self.lastDir != None:
			dlg.setCurrentDirectory(File(self.lastDir))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.saveas(path)
			
	def saveas(self,path):
		name = os.path.basename(path)
		self.codePanels.getSelectedComponent().save(path)
		self.codePanels.setTitleAt(self.codePanels.getSelectedIndex(),name)
			
	def _close(self,evt=None):
		self.close()
			
	def close(self):
		idx = self.codePanels.getSelectedIndex()
		self.codePanels.remove(idx)

	def _exit(self,evt=None):
		self.setVisible(False)
		self.dispose()

if __name__ == "__main__":	
	def usage():
		print "%s [-h] [path [path [...] ] ]" % sys.argv[0]
		print ""
		sys.exit(1)
	
	if "-h" in sys.argv:
		usage()
	
	frame = CodeEditFrame()
	
	for arg in sys.argv[1:]:
		frame.open(arg)
	
	frame.setVisible(True)
	