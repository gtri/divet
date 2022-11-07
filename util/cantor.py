#!/usr/bin/env jython
import sys
import os
import time

from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JComponent
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JScrollBar
from java.awt import Image
from java.awt.image import BufferedImage
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt.event import AdjustmentListener
from java.awt import Dimension
from java.awt import Color
from javax.swing import JFileChooser
from java.io import File
from javax.imageio import ImageIO

CACHE_THRESH = 1024*1024*10

class Cantor(JComponent):
	def __init__(self,fp,max_rgb=(0,255,0),cache=CACHE_THRESH,*args,**kwargs):
		JComponent.__init__(self)
		self.setMinimumSize(Dimension(256,256))
		self._fp = fp
		self._scale_rgb = [ float(max_c)/float(255) for max_c in max_rgb ]
		self._max_rgb   = [ max( int(max_c), 255 )  for max_c in max_rgb ]
		self._data = None
		self._fp.seek(0,2)
		self._fpsize = self._fp.tell()
		self._fp.seek(0,0)
		
		if cache == True or self._fpsize < CACHE_THRESH:
			self._data = [ord(c) for c in fp.read()]
			self._fp.seek(0,0)
		else:
			self._data = None
		
		self._offset = 0
		self._brightness = 10
		self._plotsize = min(self.maxPlotSize(),25*1024)
			
	def setOffset(self,offset):
		max_offset = self.maxOffset()
		if offset > max_offset:
			offset = max_offset
		if offset != self._offset:
			self._offset = offset
			self.repaint()
		
	def offset(self):
		return self._offset
	
	def maxOffset(self):
		return self._fpsize-self._plotsize-1
		
	def setPlotSize(self,plotsize):
		if plotsize < 1:
			plotsize = 1
		max_plotsize = self.maxPlotSize()
		if plotsize > max_plotsize:
			plotsize = max_plotsize
		if plotsize != self._plotsize:
			self._plotsize = plotsize
			max_offset = self.maxOffset()
			if self._offset > max_offset:
				self._offset = max_offset
			self.repaint()
			
	def plotSize(self):
		return self._plotsize

	def maxPlotSize(self):
		return self._fpsize-1
	
	def setBrightness(self,brightness):
		if brightness < 1:
			brightness = 1
		if brightness > self.maxBrightness():
			brightness = self.maxBrightness()
		if brightness != self._brightness:
			self._brightness = brightness
			self.repaint()

	def brightness(self):
		return self._brightness

	def maxBrightness(self):
		return 256
	
	def _get_img(self):
		if self._data == None: #File wasn't precached
			self._fp.seek(self._offset,0)
			data = [ord(c) for c in self._fp.read(self._plotsize+1)]
			offset = 0
		else: #File is completely in self._data
			data = self._data
			offset = self._offset
			
		imgdata = [0 for i in xrange(256*256)]
		for i in xrange(self._plotsize):
			coord = data[offset+i]*256+data[offset+i+1]
			imgdata[coord] = imgdata[coord] + 1
			
		jimgdata = []
		for d in imgdata:
			r = min( self._max_rgb[0], int(self._scale_rgb[0] * d*self._brightness) )
			g = min( self._max_rgb[1], int(self._scale_rgb[1] * d*self._brightness) )
			b = min( self._max_rgb[2], int(self._scale_rgb[2] * d*self._brightness) )
			jimgdata.append( (r<<16) | (g<<8) | b )
		img = BufferedImage(256,256,BufferedImage.TYPE_INT_RGB)
		img.setRGB(0,0,256,256,jimgdata,0,256)
		return img

	def paintComponent(self,g):
		img = self._get_img().getScaledInstance(self.getWidth(),self.getHeight(),0)
		g.drawImage(img,0,0,Color.RED,None)

	def snapshot(self,path):
		img = self._get_img()
		ImageIO.write(img, path[-3:], File(path))
	
		
class ScrollBarChangeListener(AdjustmentListener):
	def __init__(self,callback):
		AdjustmentListener.__init__(self)
		self.callback = callback
	def adjustmentValueChanged(self,evt):
		self.callback(evt)

class CantorControls(JFrame):
	def __init__(self,fp,max_rgb=(0,255,0)):
		JFrame.__init__(self, os.path.basename(fp.name) , defaultCloseOperation = JFrame.EXIT_ON_CLOSE, size=(300,300))
		
		self.lastDir = None
		
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.X_AXIS) )
			
		cantorPanel = JPanel()
		cantorPanel.setLayout( BoxLayout(cantorPanel,BoxLayout.Y_AXIS) )
		snapshot = JButton("Snapshot",actionPerformed=self.onSnapshot)
		snapshot.setAlignmentX(JComponent.CENTER_ALIGNMENT)
		cantorPanel.add(snapshot)
		self.cantor = Cantor(fp,max_rgb,self)
		self.scale = 1
		while self.cantor.maxPlotSize()*self.scale > 2147483647:
			self.scale = self.scale - 0.001
		cantorPanel.add(self.cantor)
		self.add(cantorPanel)
			
		offsetPanel = JPanel()
		offsetPanel.setLayout( BoxLayout(offsetPanel,BoxLayout.Y_AXIS) )
		offsetLabel = JLabel(" off ")
		offsetLabel.setAlignmentX(JComponent.CENTER_ALIGNMENT)
		offsetPanel.add(offsetLabel)
		self.offset = JScrollBar()
		self.offset.setOrientation(self.offset.VERTICAL)
		self.offset.setMinimum(0)
		self.offset.setMaximum(int(self.cantor.maxOffset()*self.scale))
		self.offset.setValue(int(self.cantor.offset()*self.scale))
		self.offset.addAdjustmentListener( ScrollBarChangeListener(self.onChangeOffset) )
		offsetPanel.add(self.offset)
		self.add(offsetPanel)
		
		plotsizePanel = JPanel()
		plotsizePanel.setLayout( BoxLayout(plotsizePanel,BoxLayout.Y_AXIS) )
		plotsizeLabel = JLabel(" len ")
		plotsizeLabel.setAlignmentX(JComponent.CENTER_ALIGNMENT)
		plotsizePanel.add(plotsizeLabel)
		self.plotsize = JScrollBar()
		self.plotsize.setOrientation(self.plotsize.VERTICAL)
		self.plotsize.setMinimum(1)
		self.plotsize.setMaximum(int(self.cantor.maxPlotSize()*self.scale))
		#self.plotsize.setInvertedAppearance(True) 
		self.plotsize.setValue(int(self.cantor.plotSize()*self.scale))
		self.plotsize.addAdjustmentListener( ScrollBarChangeListener(self.onChangePlotSize) )
		plotsizePanel.add(self.plotsize)
		self.add(plotsizePanel)
		
		brightnessPanel = JPanel()
		brightnessPanel.setLayout( BoxLayout(brightnessPanel,BoxLayout.Y_AXIS) )
		brightnessLabel = JLabel(" bri ")
		brightnessLabel.setAlignmentX(JComponent.CENTER_ALIGNMENT)
		brightnessPanel.add(brightnessLabel)
		self.brightness = JScrollBar()
		self.brightness.setOrientation(self.brightness.VERTICAL)
		self.brightness.setMinimum(1)
		self.brightness.setMaximum(self.cantor.maxBrightness())
		#self.brightness.setInvertedAppearance(True)
		self.brightness.setValue(int(self.cantor.brightness()))
		self.brightness.addAdjustmentListener( ScrollBarChangeListener(self.onChangeBrightness) )
		brightnessPanel.add(self.brightness)
		self.add(brightnessPanel)

		self.setTitle(os.path.basename(fp.name))
		
	def onChangeOffset(self,evt):
		self.cantor.setOffset(int(self.offset.getValue()/self.scale))
		
	def onChangePlotSize(self,evt):
		self.cantor.setPlotSize(int(self.plotsize.getValue()/self.scale))
		
		self.offset.setMaximum(int(self.cantor.maxOffset()*self.scale))
		self.offset.setValue(int(self.cantor.offset()*self.scale))
			
	def onChangeBrightness(self,evt):
		self.cantor.setBrightness(self.brightness.getValue())
			
	def onSnapshot(self,evt):
		dlg = JFileChooser()
		if self.lastDir != None:
			dlg.setCurrentDirectory(File(self.lastDir))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.cantor.snapshot(path)
		
def usage():
	print("Usage:")
	print("%s [-h] [-cRRGGBB] [-r[#]] bin_path" % sys.argv[0])
	print("")
	print(" -c : Set color with red, green, and blue hex values (default 00FF00)")
	print(" -r : Control read cache.  If file is less than # bytes it is cached.")
	print("      If no # is given, then cache is forced. (default is %d)" % CACHE_THRESH)
	print("")
	sys.exit(1)
		
def main():
	path = None
	max_rgb = [0x00,0xFF,0x00]
	cache = CACHE_THRESH
	for arg in sys.argv[1:]:
		if arg == "-h":
			usage()
		elif arg[:2] == "-c":
			if len(arg) != 8:
				usage()
			try:
				max_rgb = [int(arg[2:4],16), int(arg[4:6],16), int(arg[6:8],16)]
			except ValueError:
				usage()
		elif arg[:2] == "-r":
			if len(arg) > 2:
				try:
					cache = int(arg[2:])
				except ValueError:
					usage()
			else:
				cache = True
		else:
			if not os.path.exists(arg):
				usage()
			path = arg
	if path == None:
		usage()
		
	fp = open(path,"rb")

	frame = CantorControls(fp,max_rgb)
	frame.setVisible(True)

	
if __name__ == "__main__":
	main()
