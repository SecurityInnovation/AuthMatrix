# Copyright (c) 2016 Mick Ayzenberg - Security Innovation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IContextMenuFactory
from burp import IHttpRequestResponse

from java.awt import Component;
from java.awt import GridBagLayout;
from java.awt import GridBagConstraints;
from java.awt import Dimension;
from java.util import ArrayList;
from java.lang import Boolean;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JPanel;
from javax.swing import JButton;
from javax.swing import JTable;
from javax.swing import JOptionPane;
from javax.swing import JMenuItem;
from javax.swing import JCheckBox;
from javax.swing import JLabel;
from javax.swing import JFileChooser;
from javax.swing import JPopupMenu;
from javax.swing import JTextField;
from javax.swing import TransferHandler;
from javax.swing import DropMode;
from javax.swing import JSeparator;
from javax.swing import SwingConstants;
from java.awt.datatransfer import StringSelection;
from java.awt.datatransfer import DataFlavor;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import TableCellRenderer;
from javax.swing.table import JTableHeader;
from java.awt import Color;
from java.awt import Font;
from java.awt.event import MouseAdapter;
from java.awt.event import ActionListener;
from java.awt.event import ItemListener;
from java.awt.event import ItemEvent;
from javax.swing.event import DocumentListener;
from javax.swing.event import ChangeListener;
import java.lang;

from org.python.core.util import StringUtil
from threading import Lock
from threading import Thread
import traceback
import re
import urllib2
import json
import base64
import random
import string


AUTHMATRIX_VERSION = "0.6.3"

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our Burp callbacks object
        self._callbacks = callbacks
        # obtain an Burp extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("AuthMatrix - v"+AUTHMATRIX_VERSION)

        # DB that holds everything users, roles, and messages
        self._db = MatrixDB()

        # For saving/loading config
        self._fc = JFileChooser()        

        # Used by inner classes
        selfExtender = self
        self._selectedColumn = -1
        self._selectedRow = -1


        # Table of User entries
        self._userTable = UserTable(UserTableModel(self._db))
        roleScrollPane = JScrollPane(self._userTable)
        self._userTable.redrawTable()

        # Table of Request (AKA Message) entries
        self._messageTable = MessageTable(self, model = MessageTableModel(self._db))
        messageScrollPane = JScrollPane(self._messageTable)
        self._messageTable.redrawTable()

        # Set Messages to reorderable
        self._messageTable.setDragEnabled(True)
        self._messageTable.setDropMode(DropMode.INSERT_ROWS)
        self._messageTable.setTransferHandler(MessageTableRowTransferHandler(self._messageTable))                

        # Table of Chain entries
        self._chainTable = ChainTable(model = ChainTableModel(self._db))
        chainScrollPane = JScrollPane(self._chainTable)
        self._chainTable.redrawTable()


        # Semi-Generic Popup stuff
        def addPopup(component, popup):
            class genericMouseListener(MouseAdapter):
                def mousePressed(self, e):
                    if e.isPopupTrigger():
                        self.showMenu(e)
                def mouseReleased(self, e):
                    if e.isPopupTrigger():
                        self.showMenu(e)
                def showMenu(self, e):
                    # NOTE: testing if .locked is ok here since its a manual operation
                    if selfExtender._db.lock.locked():
                        return
                    
                    if type(component) is JTableHeader:
                        table = component.getTable()
                        column = component.columnAtPoint(e.getPoint())
                        # TODO wrap this string
                        if type(table) is MessageTable and column >= selfExtender._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT or type(table) is UserTable and column >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT:
                            selfExtender._selectedColumn = column
                        else:
                            return
                    else:
                        selfExtender._selectedRow = component.rowAtPoint(e.getPoint())
                    popup.show(e.getComponent(), e.getX(), e.getY())
            component.addMouseListener(genericMouseListener())

        class actionRunMessage(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        indexes = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getMessageByRow(rowNum)._index for rowNum in selfExtender._messageTable.getSelectedRows()]
                    t = Thread(target=selfExtender.runMessagesThread, args = [indexes])
                    t.start()
                    selfExtender._selectedColumn = -1
                    # Redrawing the table happens in colorcode within the thread

        class actionRemoveMessage(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        indexes = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getMessageByRow(rowNum)._index for rowNum in selfExtender._messageTable.getSelectedRows()]
                    for i in indexes:
                        selfExtender._db.deleteMessage(i)
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        class actionRemoveUser(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._userTable.getSelectedRows():
                        indexes = [selfExtender._db.getUserByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getUserByRow(rowNum)._index for rowNum in selfExtender._userTable.getSelectedRows()]
                    for i in indexes:
                        selfExtender._db.deleteUser(i)
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()

        class actionRemoveChain(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._chainTable.getSelectedRows():
                        indexes = [selfExtender._db.getChainByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getChainByRow(rowNum)._index for rowNum in selfExtender._chainTable.getSelectedRows()]
                    for i in indexes:
                        selfExtender._db.deleteChain(i)
                    selfExtender._selectedColumn = -1
                    selfExtender._chainTable.redrawTable()

        class actionRemoveRole(ActionListener):

            def __init__(self, table):
                self._table = table

            def actionPerformed(self,e):
                if selfExtender._selectedColumn >= 0:
                    selfExtender._db.deleteRole(selfExtender._db.getRoleByColumn(selfExtender._selectedColumn, self._table)._index)
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()
                    selfExtender._messageTable.redrawTable()

        class actionToggleRegex(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messages = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messages = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]
                    for m in messages:
                        m.setFailureRegex(not m.isFailureRegex())
                        m.clearResults()
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        class actionChangeDomain(ActionListener):
            def replaceDomain(self, requestResponse, newDomain):
                requestInfo = selfExtender._helpers.analyzeRequest(requestResponse)
                reqBody = requestResponse.getRequest()[requestInfo.getBodyOffset():]            
                newHeaders = ModifyMessage.getNewHeaders(requestInfo, None, "Host: "+newDomain)
                newreq = selfExtender._helpers.buildHttpMessage(newHeaders, reqBody)
                return newreq

            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messages = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messages = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]

                    service = None if len(messages)>1 else messages[0]._requestResponse.getHttpService()

                    ok, host, port, tls, replaceHost = selfExtender.changeDomainPopup(service)
                    if ok and host:
                        if not port or not port.isdigit():
                            port = 443 if tls else 80
                        for m in messages:
                            if replaceHost:
                                request = self.replaceDomain(m._requestResponse, host)
                            else:
                                request = m._requestResponse.getRequest()
                            m._requestResponse = RequestResponseStored(selfExtender, host, int(port), "https" if tls else "http", request)
                            m.clearResults()
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        # Message Table popups
        messagePopup = JPopupMenu()
        addPopup(self._messageTable,messagePopup)
        messageRun = JMenuItem("Run Request(s)")
        messageRun.addActionListener(actionRunMessage())
        messagePopup.add(messageRun)
        messageRemove = JMenuItem("Remove Request(s)")
        messageRemove.addActionListener(actionRemoveMessage())
        messagePopup.add(messageRemove)
        toggleRegex = JMenuItem("Toggle Regex Mode (Success/Failure)")
        toggleRegex.addActionListener(actionToggleRegex())
        messagePopup.add(toggleRegex)
        changeDomain = JMenuItem("Change Target Domain")
        changeDomain.addActionListener(actionChangeDomain())
        messagePopup.add(changeDomain)
        


        messageHeaderPopup = JPopupMenu()
        addPopup(self._messageTable.getTableHeader(),messageHeaderPopup)
        roleRemoveFromMessageTable = JMenuItem("Remove Role")
        roleRemoveFromMessageTable.addActionListener(actionRemoveRole("m"))
        messageHeaderPopup.add(roleRemoveFromMessageTable)

        # User Table popup
        userPopup = JPopupMenu()
        addPopup(self._userTable,userPopup)
        userRemove = JMenuItem("Remove Users(s)")
        userRemove.addActionListener(actionRemoveUser())
        userPopup.add(userRemove)

        userHeaderPopup = JPopupMenu()
        addPopup(self._userTable.getTableHeader(),userHeaderPopup)
        roleRemoveFromUserTable = JMenuItem("Remove Role")
        roleRemoveFromUserTable.addActionListener(actionRemoveRole("u"))
        userHeaderPopup.add(roleRemoveFromUserTable)

        # Chain Table popup
        chainPopup = JPopupMenu()
        addPopup(self._chainTable,chainPopup)
        chainRemove = JMenuItem("Remove Chain(s)")
        chainRemove.addActionListener(actionRemoveChain())
        chainPopup.add(chainRemove)


        # request tabs added to this tab on click in message table
        self._tabs = JTabbedPane()
        # Add change listener to set currentDisplayedItem
        class TabChangeListener(ChangeListener):
            def stateChanged(self, e):
                if type(e.getSource()) == JTabbedPane and e.getSource().getSelectedIndex()>=0:
                        selfExtender._currentlyDisplayedItem = e.getSource().getSelectedComponent()._requestResponse
        self._tabs.addChangeListener(TabChangeListener())


        # Button pannel
        buttons = JPanel()
        self._runButton = JButton("Run", actionPerformed=self.runClick)
        self._cancelButton = JButton("Cancel", actionPerformed=self.cancelClick)
        self._newUserButton = JButton("New User", actionPerformed=self.getInputUserClick)
        self._newRoleButton = JButton("New Role", actionPerformed=self.getInputRoleClick)
        self._newChainButton = JButton("New Chain (Advanced)", actionPerformed=self.newChainClick)
        self._saveButton = JButton("Save", actionPerformed=self.saveClick)
        self._loadButton = JButton("Load", actionPerformed=self.loadClick)
        self._clearButton = JButton("Clear", actionPerformed=self.clearClick)

        buttons.add(self._runButton)
        buttons.add(self._cancelButton)
        self._cancelButton.setEnabled(False)
        separator1 = JSeparator(SwingConstants.VERTICAL)
        separator1.setPreferredSize(Dimension(25,0))
        buttons.add(separator1)
        buttons.add(self._newUserButton)
        buttons.add(self._newRoleButton)
        buttons.add(self._newChainButton)
        separator2 = JSeparator(SwingConstants.VERTICAL)
        separator2.setPreferredSize(Dimension(25,0))
        buttons.add(separator2)
        buttons.add(self._saveButton)
        buttons.add(self._loadButton)
        buttons.add(self._clearButton)

        # Top pane
        firstPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,roleScrollPane,messageScrollPane)
        self._topPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, firstPane, chainScrollPane)
        bottomPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._tabs, buttons)

        # Main Pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._topPane, bottomPane)
        


        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(firstPane)
        callbacks.customizeUiComponent(self._topPane)
        callbacks.customizeUiComponent(bottomPane)
        callbacks.customizeUiComponent(messageScrollPane)
        callbacks.customizeUiComponent(roleScrollPane)
        callbacks.customizeUiComponent(chainScrollPane)
        callbacks.customizeUiComponent(self._messageTable)
        callbacks.customizeUiComponent(self._userTable)
        callbacks.customizeUiComponent(self._chainTable)
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(buttons)

        self._splitpane.setResizeWeight(0.5)
        firstPane.setResizeWeight(0.35)
        self._topPane.setResizeWeight(0.85)
        bottomPane.setResizeWeight(0.95)

        # Handles checkbox color coding
        # Must be bellow the customizeUiComponent calls
        self._messageTable.setDefaultRenderer(Boolean, SuccessBooleanRenderer(self._messageTable.getDefaultRenderer(Boolean), self._db))
        self._messageTable.setDefaultRenderer(str, RegexRenderer(self._messageTable.getDefaultRenderer(str), self._db))

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)        
        # register SendTo option
        callbacks.registerContextMenuFactory(self)

        return
        
    ##
    ## implement ITab
    ##

    
    def getTabCaption(self):
        return "AuthMatrix"
    
    def getUiComponent(self):
        return self._splitpane
       

    ##
    ## Creates the sendto tab in other areas of Burp
    ##

    def createMenuItems(self, invocation):

        def addRequestsToTab(e):
            for messageInfo in messages:
                # saveBuffers is required since modifying the original from its source changes the saved objects, its not a copy
                # TODO maybe replace with RequestResponseStored?
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                name = str(requestInfo.getMethod()).ljust(8) + requestInfo.getUrl().getPath()
                messageIndex = self._db.createNewMessage(self._callbacks.saveBuffersToTempFiles(messageInfo), name)
                #self._messageTable.getModel().addRow(row)
            self._messageTable.redrawTable()

        class UserCookiesActionListener(ActionListener):
            def __init__(self, currentUser, extender):
                self.currentUser=currentUser
                self.extender = extender

            def actionPerformed(self, e):
                for messageInfo in messages:
                    cookieVal = ""
                    requestInfo = self.extender._helpers.analyzeRequest(messageInfo)
                    for header in requestInfo.getHeaders():
                        cookieStr = "Cookie: "
                        if header.startswith(cookieStr):
                            cookieVal = header[len(cookieStr):]

                    # Grab Set-Cookie headers from the responses as well
                    response = messageInfo.getResponse()
                    if response:
                        responseInfo = self.extender._helpers.analyzeResponse(response)
                        responseCookies = responseInfo.getCookies()
                        newCookies = "; ".join([x.getName()+"="+x.getValue() for x in responseCookies])
                        cookieVal = ModifyMessage.cookieReplace(cookieVal,newCookies)

                    self.currentUser._cookies = cookieVal

                self.extender._userTable.redrawTable()

        ret = []
        messages = invocation.getSelectedMessages()

        # Check if the messages in the target tree have a response
        valid = True
        if invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE:
            for selected in messages:
                if not selected.getResponse():
                    valid = False

        if valid:
            menuItem = JMenuItem("Send request(s) to AuthMatrix");
            menuItem.addActionListener(addRequestsToTab)
            ret.append(menuItem)

            if len(messages)==1:
                # Send cookies to user:
                for i in self._db.getActiveUserIndexes():
                    user = self._db.arrayOfUsers[i]
                    menuItem = JMenuItem("Send cookies to AuthMatrix user: "+user._name);
                    menuItem.addActionListener(UserCookiesActionListener(user, self))
                    ret.append(menuItem)

        return ret
    
    ##
    ## implement IMessageEditorController
    ## this allows our request/response viewers to obtain details about the messages being displayed
    ##

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    ##
    ## Actions on Bottom Row Button Clicks
    ##

    def printDB(self, e):
        out = ""
        for a in self._db.arrayOfUsers:
            out += str(a._index)+" "+a._name+" : "+str(a._roles)+"\n"
        for b in self._db.arrayOfMessages:
            out += str(b._index)+" "+str(b._roles)+"\n"
        JOptionPane.showMessageDialog(self._splitpane,out)

    def getInputUserClick(self, e):
        newUser = JOptionPane.showInputDialog(self._splitpane,"Enter New User:")
        if not newUser is None:
            self._db.getOrCreateUser(newUser)
            self._userTable.redrawTable()

    def getInputRoleClick(self, e):
        newRole = JOptionPane.showInputDialog(self._splitpane,"Enter New Role:")
        if not newRole is None:
            self._db.getOrCreateRole(newRole)
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def newChainClick(self,e):
        self._db.createNewChain()
        self._chainTable.redrawTable()

    def cancelClick(self,e):
        self._runCancelled = True
        self._cancelButton.setEnabled(False)

    def saveClick(self, e):
        # Update original requests with any user changes
        self._messageTable.updateMessages()

        returnVal = self._fc.showSaveDialog(self._splitpane)
        if returnVal == JFileChooser.APPROVE_OPTION:
            f = self._fc.getSelectedFile()
            if f.exists():
                result = JOptionPane.showConfirmDialog(self._splitpane, "The file exists, overwrite?", "Existing File", JOptionPane.YES_NO_OPTION)
                if result != JOptionPane.YES_OPTION:
                    return
            fileName = f.getPath()
            fileout = open(fileName,'w')
            fileout.write(self._db.getSaveableJson())
            fileout.close()

    def loadClick(self,e):
        returnVal = self._fc.showOpenDialog(self._splitpane)
        if returnVal == JFileChooser.APPROVE_OPTION:
            warning = """
            CAUTION: 

            Loading a saved configuration deserializes data. 
            This action may pose a security threat to the application.
            Only proceed when the source and contents of this file is trusted. 

            Load Selected File?
            """
            result = JOptionPane.showOptionDialog(self._splitpane, warning, "Caution", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, None, ["OK", "Cancel"],"OK")
            if result != JOptionPane.YES_OPTION:
                return
            f = self._fc.getSelectedFile()
            fileName = f.getPath()
            
            filein = open(fileName,'r')
            jsonText = filein.read()
            filein.close()
            # Check if using on older state file compatible with v0.5.2 or greater
            if not jsonText or jsonText[0] !="{":
                self._db.loadLegacy(fileName,self)
            else:
                self._db.loadJson(jsonText,self)

            self._userTable.redrawTable()
            self._messageTable.redrawTable()
            self._chainTable.redrawTable()

    def clearClick(self,e):
        result = JOptionPane.showConfirmDialog(self._splitpane, "Clear AuthMatrix Configuration?", "Clear Config", JOptionPane.YES_NO_OPTION)
        if result == JOptionPane.YES_OPTION:
            self._db.clear()
            self._tabs.removeAll()
            self._userTable.redrawTable()
            self._messageTable.redrawTable()
            self._chainTable.redrawTable()

    def runClick(self,e):
        t = Thread(target=self.runMessagesThread)
        self._tabs.removeAll()
        t.start()

    def changeDomainPopup(self, service):
        hostField = JTextField(25)
        portField = JTextField(25)
        checkbox = JCheckBox()

        replaceHostCheckbox = JCheckBox()
        replaceHostCheckbox.setSelected(True)
        
        errorField = JLabel("\n")
        errorField.setForeground(Color.orange);
        errorField.setFont

        def isValidDomain(domain):
            return re.match(r'^[a-zA-Z0-9-\.]+$', domain)

        if service:
            hostField.setText(service.getHost())
            portField.setText(str(service.getPort()))
            if service.getProtocol()=="https":
                checkbox.setSelected(True)

        class HttpsItemListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED and portField.getText() == "80":                    
                    portField.setText("443")
                elif e.getStateChange() == ItemEvent.DESELECTED and portField.getText() == "443":
                    portField.setText("80")
        checkbox.addItemListener(HttpsItemListener())

        class HostDocumentListener(DocumentListener):
            def changeUpdate(self, e):
                self.testHost()
            def removeUpdate(self, e):
                self.testHost()
            def insertUpdate(self, e):
                self.testHost()

            def testHost(self):
                domain = hostField.getText()
                matches = isValidDomain(domain)
                if not matches:
                    # NOTE Hacky way to fix layout when host is long
                    if len(domain)>40:
                        domain = domain[:40]+"..."
                    errorField.setText("Invalid host: "+domain)
                else:
                    errorField.setText("\n")
        hostField.getDocument().addDocumentListener(HostDocumentListener())

        domainPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.WEST

        firstline = JPanel()
        firstline.add(JLabel("Specify the details of the server to which the request will be sent."))
        secondline = JPanel()
        secondline.add(JLabel("Host: "))
        secondline.add(hostField)
        thirdline = JPanel()
        thirdline.add(JLabel("Port: "))
        thirdline.add(portField)
        fourthline = JPanel()
        fourthline.add(checkbox)
        fourthline.add(JLabel("Use HTTPS"))
        fifthline = JPanel()
        fifthline.add(replaceHostCheckbox)
        fifthline.add(JLabel("Replace Host in HTTP header"))
        sixthline = JPanel()
        sixthline.add(errorField)

        gbc.gridy = 0
        domainPanel.add(firstline,gbc)
        gbc.gridy = 1
        domainPanel.add(secondline, gbc)
        gbc.gridy = 2
        domainPanel.add(thirdline, gbc)
        gbc.gridy = 3
        domainPanel.add(fourthline, gbc)
        gbc.gridy = 4
        domainPanel.add(fifthline, gbc)
        gbc.gridy = 5
        domainPanel.add(sixthline, gbc)


        result = JOptionPane.showConfirmDialog(
            self._splitpane,domainPanel, "Configure target details", JOptionPane.OK_CANCEL_OPTION)
        cancelled = (result == JOptionPane.CANCEL_OPTION)
        if cancelled or not isValidDomain(hostField.getText()):
            return (False, None, None, False, False)
        return (True, hostField.getText(), portField.getText(), checkbox.isSelected(), replaceHostCheckbox.isSelected())

    ##
    ## Methods for running messages and analyzing results
    ##

    def lockButtons(self, running=True):
        # Disable run button, enable cancel button
        self._runButton.setEnabled(not running)
        self._newUserButton.setEnabled(not running)
        self._newRoleButton.setEnabled(not running)
        self._newChainButton.setEnabled(not running)
        self._saveButton.setEnabled(not running)
        self._loadButton.setEnabled(not running)
        self._clearButton.setEnabled(not running)
        self._cancelButton.setEnabled(running)


    def runMessagesThread(self, messageIndexes=None):
        self._db.lock.acquire()
        try:
            self.lockButtons()
            self._runCancelled=False
            # Update original requests with any user changes
            self._messageTable.updateMessages()
            self._db.clearAllChainResults()

            indexes = messageIndexes
            if not indexes:
                indexes = self._db.getActiveMessageIndexes()
            self.clearColorResults(indexes)
            # Run in order of row, not by index
            for message in self._db.getMessagesInOrderByRow():
                if message._index in indexes:
                    self.runMessage(message._index)

        except:
            traceback.print_exc(file=self._callbacks.getStderr())
        finally:
            self.lockButtons(False)
            self._db.lock.release()
            self._messageTable.redrawTable()


    def runMessage(self, messageIndex):

        # TODO: this uses hacky threading tricks for handling timeouts, find a better way
        tempRequestResponse = []
        index = 0
        def loadRequestResponse(index, service, message):
            # NOTE: tempRequestResponse is an array because of a threading issue,
            # where if this thread times out, it will still update temprequestresponse later on..
            try:
                tempRequestResponse[index] = self._callbacks.makeHttpRequest(service,message)
            except java.lang.RuntimeException:
                # Catches if there is a bad host
                # TODO there may sometimes be an unhandled exception thrown in the stack trace here?
                print "Runtime Exception"
                return
            except:
                traceback.print_exc(file=callbacks.getStderr())

        messageEntry = self._db.arrayOfMessages[messageIndex]
        messageEntry.clearResults()

        messageInfo = messageEntry._requestResponse
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        reqBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        for userIndex in self._db.getActiveUserIndexes():
            # Handle cancel button early exit here
            if self._runCancelled:
                return


            userEntry = self._db.arrayOfUsers[userIndex]
            newHeaders = ModifyMessage.getNewHeaders(requestInfo, userEntry._cookies, userEntry._header)
            newBody = ModifyMessage.getNewBody(requestInfo, reqBody, userEntry._postargs)

            # Replace with Chain
            for toRegex, toValue in userEntry.getChainResultByMessageIndex(messageIndex):
                newBody = StringUtil.toBytes(ModifyMessage.chainReplace(toRegex,toValue,[StringUtil.fromBytes(newBody)])[0])
                newHeaders = ModifyMessage.chainReplace(toRegex,toValue,newHeaders)

            # Replace Custom Special Types (i.e. Random)
            newBody = StringUtil.toBytes(ModifyMessage.customReplace([StringUtil.fromBytes(newBody)])[0])
            newHeaders = ModifyMessage.customReplace(newHeaders)

            # Construct and send a message with the new headers
            message = self._helpers.buildHttpMessage(newHeaders, newBody)


            # Run with threading to timeout correctly   
            tempRequestResponse.append(None)         
            t = Thread(target=loadRequestResponse, args = [index,messageInfo.getHttpService(),message])
            t.start()
            t.join(self._db.LOAD_TIMEOUT)
            if t.isAlive():
                print "ERROR: Request Timeout"
            requestResponse = tempRequestResponse[index]
            if requestResponse:
                messageEntry.addRunByUserIndex(userIndex, self._callbacks.saveBuffersToTempFiles(requestResponse))

                # Get Chain Result
                response = requestResponse.getResponse()
                if not response:
                    print "ERROR: No HTTP Response (Likely Invalid Target Host)"
                else:
                    response = StringUtil.fromBytes(response)
                    for c in self._db.getActiveChainIndexes():
                        chain = self._db.arrayOfChains[c]
                        if chain._fromID == str(messageIndex) and chain._enabled:
                            # If a sourceUser is set, replace for all users' chain results
                            # Else, replace each user's chain results individually
                            replace = True
                            affectedUsers = [userEntry]
                            if chain._sourceUser:
                                if str(chain._sourceUser) == str(userIndex):
                                    affectedUsers = [self._db.arrayOfUsers[i] for i in self._db.getActiveUserIndexes()]
                                else:
                                    replace = False
                            if replace:
                                match = re.search(chain._fromRegex, response, re.DOTALL)
                                if match and len(match.groups()):
                                    result = match.group(1)
                                    for toID in chain.getToIDRange():
                                        for affectedUser in affectedUsers:
                                            affectedUser.addChainResultByMessageIndex(toID, chain._toRegex, result)
            index +=1

        # Grab all active roleIndexes that are checkboxed
        activeCheckBoxedRoles = [index for index in messageEntry._roles.keys() if messageEntry._roles[index] and not self._db.arrayOfRoles[index].isDeleted()]
        # Check Role Results of message
        for roleIndex in self._db.getActiveRoleIndexes():
            expectedResult = self.checkResult(messageEntry, roleIndex, activeCheckBoxedRoles)
            messageEntry.setRoleResultByRoleIndex(roleIndex, expectedResult)
                    

    def clearColorResults(self, messageIndexArray = None):
        if not messageIndexArray:
            messageIndexes = self._db.getActiveMessageIndexes()
        else:
            messageIndexes = messageIndexArray
        for messageIndex in messageIndexes:
            messageEntry = self._db.arrayOfMessages[messageIndex]
            messageEntry.clearResults()
        self._messageTable.redrawTable()

    def checkResult(self, messageEntry, roleIndex, activeCheckBoxedRoles):
        for userIndex in self._db.getActiveUserIndexes():
            userEntry = self._db.arrayOfUsers[userIndex]

            ignoreUser = False

            # NOTE: When using failure regex, all users not in a checked role must see that regex

            # if user is not in this role, ignore it
            if not userEntry._roles[roleIndex]:
                ignoreUser = True

            else:
                # If user is in any other checked role, then ignore it
                for index in self._db.getActiveRoleIndexes():
                    if not index == roleIndex and userEntry._roles[index]:
                        if index in activeCheckBoxedRoles:
                            ignoreUser = True
                    
            if not ignoreUser:
                if not userEntry._index in messageEntry._userRuns:
                    print "ERROR: HTTP Requests Failed During Run"
                    return False
                requestResponse = messageEntry._userRuns[userEntry._index]
                response = requestResponse.getResponse()
                if not response:
                    print "ERROR: No HTTP Response (Likely Invalid Target Host)"
                    return False
                
                resp = StringUtil.fromBytes(response)
                found = re.search(messageEntry._regex, resp, re.DOTALL)

                roleChecked = roleIndex in activeCheckBoxedRoles
                shouldSucceed = not roleChecked if messageEntry.isFailureRegex() else roleChecked 
                succeeds = found if shouldSucceed else not found
                
                
                if not succeeds:
                    return False

        return True


##
## Static methods to modify requests during runs
##
class ModifyMessage():

    @staticmethod
    def cookieReplace(oldCookieStr, newCookieStr):
        previousCookies = oldCookieStr.replace(" ","").split(";")

        newCookies = newCookieStr.replace(" ","").split(";")
        newCookieVariableNames = []
        for newCookie in newCookies:
            # If its a valid cookie
            equalsToken = newCookie.find("=")
            if equalsToken >= 0:
                newCookieVariableNames.append(newCookie[0:equalsToken+1])

        # Add all the old unchanged cookies
        for previousCookie in previousCookies:
            # If its a valid cookie
            equalsToken = previousCookie.find("=")
            if equalsToken >= 0:
                if previousCookie[0:equalsToken+1] not in newCookieVariableNames:
                    newCookies.append(previousCookie)

        # Remove whitespace
        newCookies = [x for x in newCookies if x]
        return "; ".join(newCookies)


    # Replaces headers/cookies with user's token
    @staticmethod
    def getNewHeaders(requestInfo, newCookieStr, newHeader):
        ret = requestInfo.getHeaders()
        headers = requestInfo.getHeaders()

        # Handle Cookies
        if newCookieStr:
            replaceIndex = -1
            cookieHeader = "Cookie:"
            oldCookieStr = ""
            # Find existing cookie header
            for i in range(headers.size()):
                header = headers[i]
                if str(header).startswith(cookieHeader):
                    replaceIndex = i
                    oldCookieStr = str(header)[len(cookieHeader):]

            newCookiesHeader = cookieHeader+" "+ModifyMessage.cookieReplace(oldCookieStr,newCookieStr)

            if replaceIndex >= 0:
                ret.set(replaceIndex, newCookiesHeader)
            else:
                ret.add(newCookiesHeader)

        # Handle Custom Header
        if newHeader:
            replaceIndex = -1
            # TODO: Support multiple headers with a newline somehow
            colon = newHeader.find(":")
            if colon >= 0:
                for i in range(headers.size()):
                    header = headers[i]
                    # If the header already exists, remove it
                    if str(header).startswith(newHeader[0:colon+1]):
                        replaceIndex = i
            if replaceIndex >= 0:
                ret.set(replaceIndex, newHeader)
            else:
                ret.add(newHeader)

        return ret

    # Add static CSRF token if available
    # TODO Deprecate
    @staticmethod
    def getNewBody(requestInfo, reqBody, postargs):
        
        # Kinda hacky, but for now it will add the token as long as there is some content in the post body
        # Even if its a GET request.  This screws up when original requests have no body though... oh well...
        # TODO: Currently only handles one token
        newBody = reqBody
        if postargs and len(reqBody):
            delimeter = postargs.find("=")
            if delimeter >= 0:
                csrfname = postargs[0:delimeter]
                csrfvalue = postargs[delimeter+1:]
                params = requestInfo.getParameters()
                for param in params:
                    if str(param.getName())==csrfname:
                        # Handle CSRF Tokens in Body
                        if param.getType() == 1:
                            newBody = reqBody[0:param.getValueStart()-requestInfo.getBodyOffset()] + StringUtil.toBytes(csrfvalue) + reqBody[param.getValueEnd()-requestInfo.getBodyOffset():]
                if newBody == reqBody:
                    newBody = reqBody+StringUtil.toBytes("&"+postargs)
        return newBody

    @staticmethod
    def chainReplace(toRegex, toValue, toArray):
        ret = ArrayList()
        # HACK: URLEncode only the first line (either url path or body)
        encode = True
        for to in toArray:
            match = re.search(toRegex, to, re.DOTALL)
            if match and len(match.groups()):
                if encode:
                    toValueNew = urllib2.quote(toValue)
                else:
                    toValueNew = toValue
                ret.add(to[0:match.start(1)]+toValueNew+to[match.end(1):])
            else:
                ret.add(to)
            encode=False
        return ret

    ## Method to replace custom special types in messages
    @staticmethod
    def customReplace(toArray):
        ret = ArrayList()
        customPrefix = "#{AUTHMATRIX:"
        for to in toArray:
            toNew = to
            if customPrefix in to:
                if customPrefix+"RANDOM}" in to:
                    # This will produce a random 4 char numeric string
                    # Most common use case is for APIs that reject requests that are identical to a previous request
                    randomString = ''.join(random.choice(string.digits) for _ in range(4))
                    toNew = to.replace(customPrefix+"RANDOM}",randomString)
            ret.add(toNew)

        return ret




##
## DB Class that holds all configuration data
##

class MatrixDB():

    def __init__(self):
        # Holds all custom data
        # NOTE: consider moving these constants to a different class
        self.STATIC_USER_TABLE_COLUMN_COUNT = 5
        self.STATIC_MESSAGE_TABLE_COLUMN_COUNT = 3
        self.STATIC_CHAIN_TABLE_COLUMN_COUNT = 7
        self.LOAD_TIMEOUT = 10.0
        self.BURP_SELECTED_CELL_COLOR = Color(0xFF,0xCD,0x81)

        self.lock = Lock()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.arrayOfChains = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0
        self.deletedChainCount = 0


    # Returns the index of the user, whether its new or not
    def getOrCreateUser(self, name):
        self.lock.acquire()
        userIndex = -1
        # Check if User already exits
        for i in self.getActiveUserIndexes():
            if self.arrayOfUsers[i]._name == name:
                userIndex = i
        # Add new User
        if userIndex < 0:
            userIndex = self.arrayOfUsers.size()
            self.arrayOfUsers.add(UserEntry(userIndex,
                userIndex - self.deletedUserCount,
                name))

            # Add all existing roles as unchecked
            for roleIndex in self.getActiveRoleIndexes():
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return userIndex

    # Returns the index of the role, whether its new or not
    def getOrCreateRole(self, role):
        self.lock.acquire()
        roleIndex = -1
        # Check if Role already exists
        for i in self.getActiveRoleIndexes():
            if self.arrayOfRoles[i]._name == role:
                roleIndex = i
        # Add new Role
        if roleIndex < 0:
            roleIndex = self.arrayOfRoles.size()
            self.arrayOfRoles.add(RoleEntry(roleIndex,
                roleIndex - self.deletedRoleCount,
                role))

            # Add new role to each existing user as unchecked
            for userIndex in self.getActiveUserIndexes():
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex)

            # Add new role to each existing message as unchecked
            for messageIndex in self.getActiveMessageIndexes():
                self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return roleIndex

    # Returns the Row of the new message
    # Unlike Users and Roles, allow duplicate messages
    def createNewMessage(self,messagebuffer,name):
        self.lock.acquire()
        messageIndex = self.arrayOfMessages.size()
        self.arrayOfMessages.add(MessageEntry(messageIndex, messageIndex - self.deletedMessageCount, messagebuffer, name))

        # Add all existing roles as unchecked
        for roleIndex in self.getActiveRoleIndexes():
            self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return messageIndex

    def createNewChain(self):
        self.lock.acquire()
        chainIndex = self.arrayOfChains.size()
        # Handle Example
        if chainIndex == 0:
            self.arrayOfChains.add(ChainEntry(
                chainIndex,
                chainIndex - self.deletedChainCount,
                "[Sample Chain]",
                "1",
                "StartAfter(.*?)EndAt",
                "2,4-6",
                "StartAfter(.*?)EndAt"))
        else:
            self.arrayOfChains.add(ChainEntry(chainIndex, chainIndex - self.deletedChainCount))

        self.lock.release()
        return chainIndex

    def clear(self):
        self.lock.acquire()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.arrayOfChains = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0
        self.deletedArrayCount = 0
        self.lock.release()

    def loadLegacy(self, fileName, extender):
        from java.io import ObjectOutputStream;
        from java.io import FileOutputStream;
        from java.io import ObjectInputStream;
        from java.io import FileInputStream;

        FAILURE_REGEX_SERIALIZE_CODE = "|AUTHMATRIXFAILUREREGEXPREFIX|"
        AUTHMATRIX_SERIALIZE_CODE = "|AUTHMATRIXCOOKIEHEADERSERIALIZECODE|"

        ins = ObjectInputStream(FileInputStream(fileName))
        db=ins.readObject()
        ins.close()

        self.lock.acquire()
        self.arrayOfUsers = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfMessages = ArrayList()
        self.arrayOfChains = ArrayList()
        self.deletedUserCount = db.deletedUserCount
        self.deletedRoleCount = db.deletedRoleCount
        self.deletedMessageCount = db.deletedMessageCount
        self.deletedChainCount = 0 # Updated with chain entries below in arrayofUsers


        for message in db.arrayOfMessages:
            if message._successRegex.startswith(FAILURE_REGEX_SERIALIZE_CODE):
                regex = message._successRegex[len(FAILURE_REGEX_SERIALIZE_CODE):]
                failureRegexMode=True
            else:
                regex = message._successRegex
                failureRegexMode=False
            messageEntry = RequestResponseStored(extender, message._host, message._port, message._protocol, message._requestData)
            self.arrayOfMessages.add(MessageEntry(
                message._index,
                message._tableRow,
                messageEntry,
                message._name, message._roles, regex, message._deleted, failureRegexMode))

        for role in db.arrayOfRoles:
            self.arrayOfRoles.add(RoleEntry(
                role._index,
                role._mTableColumn-3, # NOTE this is done to preserve compatability with older state files
                role._name,
                role._deleted))
        
        for user in db.arrayOfUsers:
            # NOTE to preserve backwords compatability, chains are stored here in a really hacky way
            if type(user._roles) == int:
                # Chain
                self.deletedChainCount = user._roles
                
                name=""
                sourceUser=""
                if user._name:
                    namesplit = user._name.split(AUTHMATRIX_SERIALIZE_CODE)
                    name=namesplit[0]
                    if len(namesplit)>1:
                        sourceUser=namesplit[1]

                token = user._token.split(AUTHMATRIX_SERIALIZE_CODE)
                assert(len(token)==2)
                fromID = token[0]
                fromRegex = token[1]
                staticcsrf = user._staticcsrf.split(AUTHMATRIX_SERIALIZE_CODE)
                assert(len(staticcsrf)==2)
                toID = staticcsrf[0]
                toRegex = staticcsrf[1]
                self.arrayOfChains.add(ChainEntry(
                    int(user._index),
                    int(user._tableRow),
                    name,
                    fromID,
                    fromRegex,
                    toID,
                    toRegex,
                    user._deleted,
                    sourceUser
                    ))
            else: 
                # Normal User
                token = [""] if not user._token else user._token.split(AUTHMATRIX_SERIALIZE_CODE)
                cookies = token[0]
                header = "" if len(token)==1 else token[1]
                name = "" if not user._name else user._name
                postarg = "" if not user._staticcsrf else user._staticcsrf
                self.arrayOfUsers.add(UserEntry(
                    int(user._index),
                    int(user._tableRow),
                    name,
                    user._roles,
                    user._deleted,
                    cookies,
                    header,
                    postarg))

        self.lock.release()

    def loadJson(self, jsonText, extender):
        # TODO: Weird issue where saving serialized json doesn't use correct capitalization on bools
        # This replacement might have weird results, but most are mitigated by using base64 encoding
        jsonFixed = jsonText.replace(": False",": false").replace(": True",": true")

        stateDict = json.loads(jsonFixed)

        if stateDict["version"] != AUTHMATRIX_VERSION:
            print "Invalid Version in State File ("+stateDict["version"]+")"
            return

        self.lock.acquire()
        self.arrayOfUsers = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfMessages = ArrayList()
        self.arrayOfChains = ArrayList()
        self.deletedUserCount = stateDict["deletedUserCount"]
        self.deletedRoleCount = stateDict["deletedRoleCount"]
        self.deletedMessageCount = stateDict["deletedMessageCount"]
        self.deletedChainCount = stateDict["deletedChainCount"]

        for roleEntry in stateDict["arrayOfRoles"]:
            self.arrayOfRoles.add(RoleEntry(
                roleEntry["index"],
                roleEntry["column"],
                roleEntry["name"],
                roleEntry["deleted"]))


        for userEntry in stateDict["arrayOfUsers"]:
            self.arrayOfUsers.add(UserEntry(
                userEntry["index"],
                userEntry["tableRow"],
                userEntry["name"],
                {int(x): userEntry["roles"][x] for x in userEntry["roles"].keys()}, # convert keys to ints
                userEntry["deleted"],
                base64.b64decode(userEntry["cookiesBase64"]),
                base64.b64decode(userEntry["headerBase64"]),
                base64.b64decode(userEntry["postargsBase64"])))

        # TODO chainResults?
        
        for messageEntry in stateDict["arrayOfMessages"]:
            self.arrayOfMessages.add(MessageEntry(
                messageEntry["index"],
                messageEntry["tableRow"],
                RequestResponseStored(
                    extender,
                    messageEntry["host"],
                    messageEntry["port"],
                    messageEntry["protocol"],
                    StringUtil.toBytes(base64.b64decode(messageEntry["requestBase64"]))),
                messageEntry["name"], 
                {int(x): messageEntry["roles"][x] for x in messageEntry["roles"].keys()}, # convert keys to ints
                base64.b64decode(messageEntry["regexBase64"]), 
                messageEntry["deleted"], 
                messageEntry["failureRegexMode"]))

        # TODO roleResults and userRuns (need to convert keys)

        for chainEntry in stateDict["arrayOfChains"]:
            self.arrayOfChains.add(ChainEntry(
                chainEntry["index"],
                chainEntry["tableRow"],
                chainEntry["name"],
                chainEntry["fromID"],
                base64.b64decode(chainEntry["fromRegexBase64"]),
                chainEntry["toID"],
                base64.b64decode(chainEntry["toRegexBase64"]),
                chainEntry["deleted"],
                chainEntry["sourceUser"],
                chainEntry["enabled"]
                ))
        
        # TODO fromStart, fromEnd, toStart, toEnd?

        self.lock.release()



    def getSaveableJson(self):

        stateDict = {"version":AUTHMATRIX_VERSION,
        "deletedUserCount":self.deletedUserCount,
        "deletedRoleCount":self.deletedRoleCount,
        "deletedMessageCount":self.deletedMessageCount,
        "deletedChainCount":self.deletedChainCount}

        stateDict["arrayOfRoles"] = []
        for roleEntry in self.arrayOfRoles:
            stateDict["arrayOfRoles"].append({
                    "index":roleEntry._index,
                    "name":roleEntry._name,
                    "deleted":roleEntry._deleted,
                    "column":roleEntry._column
                })

        stateDict["arrayOfUsers"] = []
        for userEntry in self.arrayOfUsers:
            stateDict["arrayOfUsers"].append({
                    "index":userEntry._index,
                    "name":userEntry._name,
                    "roles":userEntry._roles,
                    "deleted":userEntry._deleted,
                    "tableRow":userEntry._tableRow,
                    "cookiesBase64":base64.b64encode(userEntry._cookies),
                    "headerBase64":base64.b64encode(userEntry._header),
                    "postargsBase64":base64.b64encode(userEntry._postargs),
                    "chainResults":userEntry._chainResults
                })

        stateDict["arrayOfMessages"] = []
        for messageEntry in self.arrayOfMessages:

            stateDict["arrayOfMessages"].append({
                    "index":messageEntry._index, 
                    "tableRow":messageEntry._tableRow,
                    "requestBase64":base64.b64encode(StringUtil.fromBytes(messageEntry._requestResponse.getRequest())),
                    "host":messageEntry._requestResponse.getHttpService().getHost(),
                    "port":messageEntry._requestResponse.getHttpService().getPort(),
                    "protocol":messageEntry._requestResponse.getHttpService().getProtocol(),
                    "name":messageEntry._name, 
                    "roles":messageEntry._roles, 
                    "regexBase64":base64.b64encode(messageEntry._regex), 
                    "deleted":messageEntry._deleted,
                    "failureRegexMode":messageEntry._failureRegexMode,
                    "runBase64ForUserID":{int(x): {
                        "request": base64.b64encode(StringUtil.fromBytes(messageEntry._userRuns[x].getRequest())),
                        "response": base64.b64encode(StringUtil.fromBytes(messageEntry._userRuns[x].getResponse()))}
                        for x in messageEntry._userRuns.keys()},
                    "runResultForRoleID":messageEntry._roleResults
                })

        stateDict["arrayOfChains"] = []
        for chainEntry in self.arrayOfChains:
            stateDict["arrayOfChains"].append({
                    "index":chainEntry._index,
                    "fromID":chainEntry._fromID,
                    "fromRegexBase64":base64.b64encode(chainEntry._fromRegex),
                    "toID":chainEntry._toID,
                    "toRegexBase64":base64.b64encode(chainEntry._toRegex),
                    "deleted":chainEntry._deleted,
                    "tableRow":chainEntry._tableRow,
                    "name":chainEntry._name,
                    "sourceUser":chainEntry._sourceUser,
                    "enabled":chainEntry._enabled,
                    "fromStart":chainEntry._fromStart,
                    "fromEnd":chainEntry._fromEnd,
                    "toStart":chainEntry._toStart,
                    "toEnd":chainEntry._toEnd
                })

        # BUG: this is not using the correct capitalization on booleans after loading legacy states
        return json.dumps(stateDict)

    def getActiveUserIndexes(self):
        return [x._index for x in self.arrayOfUsers if not x.isDeleted()]

    def getActiveRoleIndexes(self):
        return [x._index for x in self.arrayOfRoles if not x.isDeleted()]

    def getActiveMessageIndexes(self):
        return [x._index for x in self.arrayOfMessages if not x.isDeleted()]

    def getActiveChainIndexes(self):
        return [x._index for x in self.arrayOfChains if not x.isDeleted()]        

    def getActiveUserCount(self):
        return self.arrayOfUsers.size()-self.deletedUserCount

    def getActiveRoleCount(self):
        return self.arrayOfRoles.size()-self.deletedRoleCount

    def getActiveMessageCount(self):
        return self.arrayOfMessages.size()-self.deletedMessageCount

    def getActiveChainCount(self):
        return self.arrayOfChains.size()-self.deletedChainCount    

    def getMessageByRow(self, row):
        for m in self.arrayOfMessages:
            if not m.isDeleted() and m.getTableRow() == row:
                return m

    def getUserByRow(self, row):
        for u in self.arrayOfUsers:
            if not u.isDeleted() and u.getTableRow() == row:
                return u

    def getRoleByColumn(self,column, table):
        staticcount = self.STATIC_MESSAGE_TABLE_COLUMN_COUNT if table == "m" else self.STATIC_USER_TABLE_COLUMN_COUNT
        for r in self.arrayOfRoles:
            if not r.isDeleted() and r.getColumn()+staticcount == column:
                return r

    def getChainByRow(self, row):
        for c in self.arrayOfChains:
            if not c.isDeleted() and c.getTableRow() == row:
                return c

    def deleteUser(self,userIndex):
        self.lock.acquire()
        userEntry = self.arrayOfUsers[userIndex]
        if userEntry:
            userEntry.setDeleted()
            self.deletedUserCount += 1

            previousRow = userEntry.getTableRow()
            for i in self.getActiveUserIndexes():
                user = self.arrayOfUsers[i]
                if user.getTableRow()>previousRow:
                    user.setTableRow(user.getTableRow()-1)

        self.lock.release()

    def deleteRole(self,roleIndex):
        self.lock.acquire()
        roleEntry = self.arrayOfRoles[roleIndex]
        if roleEntry:
            roleEntry.setDeleted()
            self.deletedRoleCount += 1

            previousColumn = roleEntry.getColumn()
            for i in self.getActiveRoleIndexes():
                role = self.arrayOfRoles[i]
                if role.getColumn()>previousColumn:
                    role.setColumn(role.getColumn()-1)

        self.lock.release()

    def deleteMessage(self,messageIndex):
        self.lock.acquire()
        messageEntry = self.arrayOfMessages[messageIndex]
        if messageEntry:
            messageEntry.setDeleted()
            self.deletedMessageCount += 1

            previousRow = messageEntry.getTableRow()
            for i in self.getActiveMessageIndexes():
                message = self.arrayOfMessages[i]
                if message.getTableRow()>previousRow:
                    message.setTableRow(message.getTableRow()-1)

        self.lock.release()

    def deleteChain(self,chainIndex):
        self.lock.acquire()
        chainEntry = self.arrayOfChains[chainIndex]
        if chainEntry:
            chainEntry.setDeleted()
            self.deletedChainCount += 1

            previousRow = chainEntry.getTableRow()
            for i in self.getActiveChainIndexes():
                chain = self.arrayOfChains[i]
                if chain.getTableRow()>previousRow:
                    chain.setTableRow(chain.getTableRow()-1)

        self.lock.release()            

    def getMessagesInOrderByRow(self):
        messages = []
        for i in range(self.getActiveMessageCount()):
            messages.append(self.getMessageByRow(i))
        return messages

    def moveMessageToRow(self, fromRow, toRow):
        self.lock.acquire()
        messages = self.getMessagesInOrderByRow()
        if fromRow > toRow:
            messages[fromRow].setTableRow(toRow)
            for i in range(toRow,fromRow):
                messages[i].setTableRow(i+1)

        elif toRow > fromRow:
            messages[fromRow].setTableRow(toRow-1)
            for i in range(fromRow+1,toRow):
                messages[i].setTableRow(i-1)

        self.lock.release()

    def clearAllChainResults(self):
        for i in self.getActiveUserIndexes():
            self.arrayOfUsers[i].clearChainResults()

    def getUserByName(self, name):
        for i in self.getActiveUserIndexes():
            if self.arrayOfUsers[i]._name == name:
                return self.arrayOfUsers[i]

##
## Tables and Table Models  
##
    
class UserTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return self._db.getActiveUserCount()

    def getColumnCount(self):
        return self._db.getActiveRoleCount()+self._db.STATIC_USER_TABLE_COLUMN_COUNT

        
    def getColumnName(self, columnIndex):

        if columnIndex == 0:
            return "ID"
        elif columnIndex == 1:
            return "User Name"
        elif columnIndex == 2:
            return "Cookies"
        elif columnIndex == 3:
            return "HTTP Header"
        elif columnIndex == 4:
            return "POST Parameter"
        else:
            roleEntry = self._db.getRoleByColumn(columnIndex, 'u')
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        userEntry = self._db.getUserByRow(rowIndex)
        if userEntry:
            if columnIndex == 0:
                return userEntry._index
            elif columnIndex == 1:
                return userEntry._name
            elif columnIndex == 2:
                return userEntry._cookies
            elif columnIndex == 3:
                return userEntry._header
            elif columnIndex == 4:
                return userEntry._postargs
            else:
                roleEntry = self._db.getRoleByColumn(columnIndex, 'u')
                if roleEntry:
                    roleIndex = roleEntry._index
                    return roleIndex in userEntry._roles and userEntry._roles[roleIndex]
        return ""

    def addRow(self, row):
        self.fireTableRowsInserted(row,row)

    def setValueAt(self, val, row, col):
        # NOTE: testing if .locked is ok here since its a manual operation
        if self._db.lock.locked():
            return
        userEntry = self._db.getUserByRow(row)
        if userEntry:
            if col == 1:
                userEntry._name = val
            elif col == 2:
                userEntry._cookies = val
            elif col == 3:
                userEntry._header = val
            elif col == 4:
                userEntry._postargs = val
            else:
                roleIndex = self._db.getRoleByColumn(col, 'u')._index
                userEntry.addRoleByIndex(roleIndex, val)

        self.fireTableCellUpdated(row,col)

    # Set checkboxes and role editable
    def isCellEditable(self, row, col):
        if col > 0:
            return True
        return False
        
    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex < self._db.STATIC_USER_TABLE_COLUMN_COUNT:
            return str
        else:
            return Boolean


class UserTable(JTable):

    def __init__(self, model):
        self.setModel(model)
        return

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()
        
        # Resize
        # ID
        self.getColumnModel().getColumn(0).setMinWidth(30);
        self.getColumnModel().getColumn(0).setMaxWidth(30);


        # User Name
        self.getColumnModel().getColumn(1).setMinWidth(100);
        self.getColumnModel().getColumn(1).setMaxWidth(1000);

        # Cookie
        self.getColumnModel().getColumn(2).setMinWidth(120);
        self.getColumnModel().getColumn(2).setMaxWidth(1500);

        # Header
        self.getColumnModel().getColumn(3).setMinWidth(120);
        self.getColumnModel().getColumn(3).setMaxWidth(1500);

        # POST args
        self.getColumnModel().getColumn(4).setMinWidth(120);
        self.getColumnModel().getColumn(4).setMaxWidth(1500);

        self.getTableHeader().getDefaultRenderer().setHorizontalAlignment(JLabel.CENTER)


class MessageTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return self._db.getActiveMessageCount()
        
    def getColumnCount(self):
        return self._db.getActiveRoleCount()+self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        elif columnIndex == 1:
            return "Request Name"
        elif columnIndex == 2:
            return "Response Regex"
        else:
            roleEntry = self._db.getRoleByColumn(columnIndex, 'm')
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        messageEntry = self._db.getMessageByRow(rowIndex)
        if messageEntry:
            if columnIndex == 0:
                return str(messageEntry._index)
            elif columnIndex == 1:
                return messageEntry._name
            elif columnIndex == 2:
                return messageEntry._regex
            else:
                roleEntry = self._db.getRoleByColumn(columnIndex, 'm')
                if roleEntry:
                    roleIndex = roleEntry._index
                    return roleIndex in messageEntry._roles and messageEntry._roles[roleIndex]
        return ""

    def addRow(self, row):
        self.fireTableRowsInserted(row,row)

    def setValueAt(self, val, row, col):
        # NOTE: testing if .locked is ok here since its a manual operation
        if self._db.lock.locked():
            return
        messageEntry = self._db.getMessageByRow(row)
        if messageEntry:
            if col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-2:
                messageEntry._name = val
            elif col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
                messageEntry._regex = val
            else:
                roleIndex = self._db.getRoleByColumn(col, 'm')._index
                messageEntry.addRoleByIndex(roleIndex,val)
    
            # Update the checkbox result colors since there was a change
            if col >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
                messageEntry.clearResults()
                self.fireTableCellUpdated(row,col)
                for i in range(self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT, self.getColumnCount()):
                    self.fireTableCellUpdated(row,i)
                # Backup option
                # Update entire table since it affects color
                # self.fireTableDataChanged()

    # Set checkboxes editable
    def isCellEditable(self, row, col):
        # Include regex
        if col >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-2:
            return True
        return False

    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex < self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT:
            return str
        else:
            return Boolean



class MessageTable(JTable):

    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)
        self._viewerMap = {}
        return
    
    def changeSelection(self, row, col, toggle, extend):
        # show the message entry for the selected row
        selectedMessage = self.getModel()._db.getMessageByRow(row)

        # Update messages with any user edits to original requests:
        self.updateMessages()
        self._extender._tabs.removeAll()

        # NOTE: testing if .locked is ok here since its a manual operation
        if self.getModel()._db.lock.locked():
            # Provide some feedback on a click
            self.redrawTable()
            return

        # Create original Request tab and set default tab to Request
        # Then Create test tabs and set the default tab to Response for easy analysis
        originalTab = self.createRequestTabs(selectedMessage._requestResponse, True, selectedMessage._index)
        originalTab.setSelectedIndex(0)
        self._extender._tabs.addTab("Original",originalTab)
        for userIndex in selectedMessage._userRuns.keys():
            if not self.getModel()._db.arrayOfUsers[userIndex].isDeleted():
                tabname = str(self.getModel()._db.arrayOfUsers[userIndex]._name)
                self._extender._tabs.addTab(tabname,self.createRequestTabs(selectedMessage._userRuns[userIndex]))
                
        JTable.changeSelection(self, row, col, toggle, extend)
        return

    def createRequestTabs(self, requestResponse, original=False, index=-1):
        
        class RequestResponseTabbedPane(JTabbedPane):
            def __init__(self, requestResponse):
                self._requestResponse=requestResponse

        requestTabs = RequestResponseTabbedPane(requestResponse)
        requestViewer = self._extender._callbacks.createMessageEditor(self._extender, original)
        responseViewer = self._extender._callbacks.createMessageEditor(self._extender, False)
        requestTabs.addTab("Request", requestViewer.getComponent())
        requestTabs.addTab("Response", responseViewer.getComponent())
        self._extender._callbacks.customizeUiComponent(requestTabs)
        requestViewer.setMessage(requestResponse.getRequest(), True)
        if requestResponse.getResponse():
            responseViewer.setMessage(requestResponse.getResponse(), False)
            requestTabs.setSelectedIndex(1)

        if original and index>=0:
            self._viewerMap[index] = requestViewer

        return requestTabs

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()

        # Resize
        self.getColumnModel().getColumn(0).setMinWidth(30);
        self.getColumnModel().getColumn(0).setMaxWidth(30);
        self.getColumnModel().getColumn(1).setMinWidth(300);
        self.getColumnModel().getColumn(2).setMinWidth(150);

    def updateMessages(self):
        # For now it sounds like this does not need to be locked, since its only manual operations
        for messageIndex in self._viewerMap:
            requestViewer = self._viewerMap[messageIndex]
            if requestViewer and requestViewer.isMessageModified(): # TODO BUG: this doesnt detect change body encoding or change request method
                messageEntry = self.getModel()._db.arrayOfMessages[messageIndex]
                newMessage = requestViewer.getMessage()
                messageEntry._requestResponse = RequestResponseStored(self._extender, request=newMessage, httpService=messageEntry._requestResponse.getHttpService())                
        self._viewerMap = {}




###
### Chain Tables
###

class ChainTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return self._db.getActiveChainCount()
        
    def getColumnCount(self):
        # Disable if there arent any chains
        if not self._db.getActiveChainCount():
            return 1
        return self._db.STATIC_CHAIN_TABLE_COLUMN_COUNT

    def getColumnName(self, columnIndex):
        if self.getColumnCount() == 1:
            return ""

        if columnIndex == 0:
            return "Enabled"
        elif columnIndex == 1:
            return "Chain Name"
        elif columnIndex == 2:
            return "SRC - Message ID"
        elif columnIndex == 3:
            return "SRC - User ID (Pitchfork Mode)" # TODO Rename
        elif columnIndex == 4:
            return "Regex - Extract from HTTP Response"
        elif columnIndex == 5:
            return "DEST - Message ID(s)"
        elif columnIndex == 6:
            return "Regex - Replace into HTTP Request"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if self.getColumnCount() == 1:
            return ""

        chainEntry = self._db.getChainByRow(rowIndex)
        if chainEntry:
            if columnIndex == 0:
                return chainEntry._enabled
            elif columnIndex == 1:
                return chainEntry._name
            elif columnIndex == 2:
                return chainEntry._fromID
            elif columnIndex == 3:
                return chainEntry._sourceUser
            elif columnIndex == 4:
                return chainEntry._fromRegex
            elif columnIndex == 5:
                return chainEntry._toID
            elif columnIndex == 6:
                return chainEntry._toRegex
        return ""

    def addRow(self, row):
        self.fireTableRowsInserted(row,row)

    def setValueAt(self, val, row, col):
        # NOTE: testing if .locked is ok here since its a manual operation
        if self._db.lock.locked():
            return
        chainEntry = self._db.getChainByRow(row)
        if chainEntry:
            if col == 0:
                chainEntry._enabled = val
            elif col == 1:
                chainEntry._name = val
            elif col == 2:
                chainEntry._fromID = val
            elif col == 3:
                chainEntry._sourceUser = val
            elif col == 4:
                chainEntry._fromRegex = val
            elif col == 5:
                chainEntry._toID = val
            elif col == 6:
                chainEntry._toRegex = val


    def isCellEditable(self, row, col):
        if col >= 0:
            return True
        return False

    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            return Boolean
        return str
        


class ChainTable(JTable):

    def __init__(self, model):
        self.setModel(model)
        return

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()
        
        # Resize

        if self.getModel().getColumnCount() > 1:
            self.getColumnModel().getColumn(0).setMinWidth(60);
            self.getColumnModel().getColumn(0).setMaxWidth(60);
            self.getColumnModel().getColumn(1).setMinWidth(120);
            self.getColumnModel().getColumn(1).setMaxWidth(240);
            self.getColumnModel().getColumn(2).setMinWidth(150);
            self.getColumnModel().getColumn(2).setMaxWidth(150);        
            self.getColumnModel().getColumn(3).setMinWidth(210);
            self.getColumnModel().getColumn(3).setMaxWidth(210);        
            self.getColumnModel().getColumn(4).setMinWidth(180);
            self.getColumnModel().getColumn(5).setMinWidth(150);
            self.getColumnModel().getColumn(5).setMaxWidth(150);        
            self.getColumnModel().getColumn(6).setMinWidth(180);


# For color-coding checkboxes in the message table
class SuccessBooleanRenderer(JCheckBox,TableCellRenderer):

    def __init__(self, defaultCellRender, db):
        self.setOpaque(True)
        self.setHorizontalAlignment(JLabel.CENTER)
        self._defaultCellRender = defaultCellRender
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        if value:
            cell.setSelected(True)
        else:
            cell.setSelected(False)
        if isSelected:
            cell.setForeground(table.getSelectionForeground())
            cell.setBackground(table.getSelectionBackground())
        else:
            cell.setForeground(table.getForeground())
            cell.setBackground(table.getBackground())

        # Color based on results
        if column >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT:
            messageEntry = self._db.getMessageByRow(row)
            if messageEntry:
                roleEntry = self._db.getRoleByColumn(column, 'm')
                if roleEntry:
                    roleIndex = roleEntry._index
                    if not roleIndex in messageEntry._roleResults:
                        if isSelected:
                            cell.setBackground(self._db.BURP_SELECTED_CELL_COLOR)
                        else:
                            cell.setBackground(table.getBackground())
                    else:
                        # This site was used for generating color blends when selected (option 6 of 12)
                        # http://meyerweb.com/eric/tools/color-blend/#FFCD81:00CCFF:10:hex
                        sawExpectedResults = messageEntry._roleResults[roleIndex]
                        checkboxChecked = messageEntry._roles[roleIndex]

                        # NOTE: currently no way to detect false positive in failure mode
                        # failureRegexMode = messageEntry.isFailureRegex()

                        if sawExpectedResults:
                            # Set Green if success
                            if isSelected:
                                cell.setBackground(Color(0xC8,0xE0,0x51))
                            else:
                                cell.setBackground(Color(0x87,0xf7,0x17))
                        elif checkboxChecked:
                            # Set Blue if its probably a false positive
                            if isSelected:
                                cell.setBackground(Color(0x8B, 0xCD, 0xBA))
                            else:
                                cell.setBackground(Color(0x00,0xCC,0xFF))
                        else:
                            # Set Red if fail
                            if isSelected:
                                cell.setBackground(Color(0xFF, 0x87, 0x51))
                            else:
                                cell.setBackground(Color(0xFF, 0x32, 0x17))

        return cell
      

# For color-coding successregex in the message table
class RegexRenderer(JLabel, TableCellRenderer):

    def __init__(self, defaultCellRender, db):
        self._defaultCellRender = defaultCellRender
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Regex color
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)

        if column == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
            messageEntry = self._db.getMessageByRow(row)
            if messageEntry:
                if messageEntry.isFailureRegex():
                    # Set Grey if failure mode
                    if isSelected:
                        cell.setBackground(Color(0xD1,0xB5,0xA3))
                    else:
                        cell.setBackground(Color(0x99,0x99,0xCC))
                else:
                    if isSelected:
                        cell.setBackground(self._db.BURP_SELECTED_CELL_COLOR)
                    else:
                        cell.setBackground(table.getBackground())
        else:
            if isSelected:
                cell.setBackground(self._db.BURP_SELECTED_CELL_COLOR)
            else:
                cell.setBackground(table.getBackground())
        return cell





##
## Classes for Messages, Roles, and Users
##

class MessageEntry:

    def __init__(self, index, tableRow, requestResponse, name = "", roles = {}, regex = "^HTTP/1\\.1 200 OK", deleted = False, failureRegexMode = False):
        self._index = index
        self._tableRow = tableRow
        self._requestResponse = requestResponse
        self._name = name
        self._roles = roles.copy()
        self._failureRegexMode = failureRegexMode
        self._regex = regex
        self._deleted = deleted
        self._userRuns = {}
        self._roleResults = {}
        return

    # Role are the index of the db Role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self,roleIndex,enabled=False):
        self._roles[roleIndex] = enabled;

    # Add one Run Result of user x message
    def addRunByUserIndex(self,userIndex,requestResponse):
        self._userRuns[userIndex] = requestResponse

    def setRoleResultByRoleIndex(self, roleIndex, roleResult):
        self._roleResults[roleIndex] = roleResult

    def setDeleted(self):
        self._deleted = True

    def isDeleted(self):
        return self._deleted

    def setTableRow(self, row):
        self._tableRow = row

    def getTableRow(self):
        return self._tableRow

    def isFailureRegex(self):
        return self._failureRegexMode

    def setFailureRegex(self, enabled=True):
        self._failureRegexMode = enabled

    def clearResults(self):
        # Clear Previous Results:
        self._roleResults = {}
        self._userRuns = {}

class UserEntry:

    def __init__(self, index, tableRow, name, roles = {}, deleted=False, cookies="", header="", postargs=""):
        self._index = index
        self._name = name
        self._roles = roles.copy()
        self._deleted = deleted
        self._tableRow = tableRow
        self._cookies = cookies
        self._header = header
        self._postargs = postargs
        self._chainResults = {}
        return

    # Roles are the index of the db role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self, roleIndex, enabled=False):
        self._roles[roleIndex] = enabled

    def addChainResultByMessageIndex(self, toID, toRegex, toValue):
        if not toID in self._chainResults:
            self._chainResults[toID] = [(toRegex, toValue)]
        else:
            self._chainResults[toID].append((toRegex, toValue))

    def getChainResultByMessageIndex(self, toID):
        if toID in self._chainResults:
            return self._chainResults[toID]
        return []

    def clearChainResults(self):
        self._chainResults = {}

    def setDeleted(self):
        self._deleted = True

    def isDeleted(self):
        return self._deleted

    def setTableRow(self, row):
        self._tableRow = row

    def getTableRow(self):
        return self._tableRow

class RoleEntry:

    def __init__(self,index,columnIndex,name,deleted=False):
        self._index = index
        self._name = name
        self._deleted = deleted
        self._column = columnIndex
        return

    def setDeleted(self):
        self._deleted = True

    def isDeleted(self):
        return self._deleted

    # NOTE: in v0.6 this value was changed to index into the dynamic columns only
    def setColumn(self, column):
        self._column = column

    def getColumn(self):
        return self._column

class ChainEntry:

    def __init__(self, index, tableRow, name="", fromID="", fromRegex="", toID="", toRegex="", deleted=False, sourceUser="", enabled=False):
        self._index = index
        self._fromID = fromID
        self._fromRegex = fromRegex
        self._toID = toID
        self._toRegex = toRegex
        self._deleted = deleted
        self._tableRow = tableRow
        self._name = name
        self._sourceUser = sourceUser
        self._enabled = enabled
        self._fromStart = ""
        self._fromEnd = ""
        self._toStart = ""
        self._toEnd = ""
        return

    def setDeleted(self):
        self._deleted = True

    def isDeleted(self):
        return self._deleted    

    def setTableRow(self, row):
        self._tableRow = row

    def getTableRow(self):
        return self._tableRow

    def getFromStart(self):
        return self._fromStart

    def getFromEnd(self):
        return self._fromEnd

    def getToStart(self):
        return self._toStart

    def getToEnd(self):
        return self._toEnd

    def setFromStart(self, fromStart):
        self._fromStart = fromStart
        if self._fromEnd:
            self._fromRegex = self.getRexeg(self._fromStart,self._fromEnd)

    def setFromEnd(self, fromEnd):
        self._fromEnd = fromEnd
        if self._fromStart:
            self._fromRegex = self.getRexeg(self._fromStart,self._fromEnd)

    def setToStart(self, toStart):
        self._toStart = toStart
        if self._toEnd:
            self._toRegex = self.getRexeg(self._toStart,self._toEnd)

    def setToEnd(self, toEnd):
        self._toEnd = toEnd
        if self._toStart:
            self._toRegex = self.getRexeg(self._toStart,self._toEnd)

    def getRexegFromStartAndEnd(self,start,end):
        # TODO encode special chars
        return start+"(.*?)"+end

    def getToIDRange(self):
        result = []
        for part in self._toID.split(','):
            if '-' in part:
                a,b = part.split('-')
                if a.isdigit() and b.isdigit():
                    a,b = int(a),int(b)
                    result.extend(range(a,b+1))
            else:
                if part.isdigit():
                    a = int(part)
                    result.append(a)
        return result


##
## RequestResponse Implementation
##

class RequestResponseStored(IHttpRequestResponse):

    def __init__(self, extender, host=None, port=None, protocol=None, request=None, response=None, comment=None, highlight=None, httpService=None, requestResponse=None):
        self._extender=extender
        self._host=host
        self._port=port
        self._protocol=protocol
        self._request=request
        self._response=response
        self._comment=comment
        self._highlight=highlight
        if httpService:
            self.setHttpService(httpService)
        if requestResponse:
            self.cast(requestResponse)
        return

    def getComment(self):
        return self._comment

    def getHighlight(self):
        return self._highlight

    def getHttpService(self):
        service = self._extender._helpers.buildHttpService(self._host, self._port, self._protocol)
        if service:
            return service
        return None

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, comment):
        self._comment = comment
        return

    def setHighlight(self, color):
        self._highlight = color
        return

    def setHttpService(self, httpService):
        self._host=httpService.getHost()
        self._port=httpService.getPort()
        self._protocol=httpService.getProtocol()
        return

    def setRequest(self, message):
        self._request = message
        return

    def setResponse(self, message):
        self._response = message
        return

    def cast(self, requestResponse):
        self.setComment(requestResponse.getComment())
        self.setHighlight(requestResponse.getHighlight())
        self.setHttpService(requestResponse.getHttpService())
        self.setRequest(requestResponse.getRequest())
        self.setResponse(requestResponse.getResponse())


##
## Drag and Drop
##

class MessageTableRowTransferHandler(TransferHandler):

    def __init__(self, table):
        self._table = table

    def createTransferable(self, c):
        assert(c == self._table)
        return StringSelection(str(c.getSelectedRow()))

    def getSourceActions(self, c):
        return TransferHandler.COPY_OR_MOVE

    def exportDone(self, c, t, act):
        if act == TransferHandler.MOVE or act == TransferHandler.NONE:
            self._table.redrawTable()


    def canImport(self, info):
        b = info.getComponent() == self._table and info.isDrop() and info.isDataFlavorSupported(DataFlavor.stringFlavor)
        return b

    def importData(self, info):
        target = info.getComponent()
        dl = info.getDropLocation()
        index = dl.getRow()
        tablemax = self._table.getModel().getRowCount()
        if index < 0 or index > tablemax:
            index = tablemax

        rowFrom = info.getTransferable().getTransferData(DataFlavor.stringFlavor)
        #print "Moving row "+str(rowFrom)+" to row "+str(index)
        self._table.getModel()._db.moveMessageToRow(int(rowFrom), int(index))
        return True



##
## LEGACY SERIALIZABLE CLASSES
##

# Serializable DB
# Used to store Database to Disk on Save and Load
class MatrixDBData():

    def __init__(self, arrayOfMessages, arrayOfRoles, arrayOfUsers, deletedUserCount, deletedRoleCount, deletedMessageCount):
        
        self.arrayOfMessages = arrayOfMessages
        self.arrayOfRoles = arrayOfRoles
        self.arrayOfUsers = arrayOfUsers
        self.deletedUserCount = deletedUserCount
        self.deletedRoleCount = deletedRoleCount
        self.deletedMessageCount = deletedMessageCount

# Serializable MessageEntry
# Used since the Burp RequestResponse object can not be serialized
class MessageEntryData:

    def __init__(self, index, tableRow, requestData, host, port, protocol, name, roles, successRegex, deleted):
        self._index = index
        self._tableRow = tableRow
        self._requestData = requestData
        self._host = host
        self._port = port
        self._protocol = protocol
        self._url = "" # NOTE obsolete, kept for backwords compatability
        self._name = name
        self._roles = roles
        # NOTE: to preserve backwords compatability, successregex will have a specific prefix "|AMFAILURE|" to indicate FailureRegexMode
        self._successRegex = successRegex
        self._deleted = deleted
        return

class RoleEntryData:

    def __init__(self,index,mTableColumnIndex,uTableColumnIndex,name,deleted):
        self._index = index
        self._name = name
        self._deleted = deleted
        # NOTE: to preserve backwords compatibility, these will be the dynamic column +3
        self._mTableColumn = mTableColumnIndex
        self._uTableColumn = uTableColumnIndex
        return

class UserEntryData:

    def __init__(self, index, tableRow, name, roles, deleted, token, staticcsrf):
        self._index = index
        self._name = name
        self._roles = roles
        self._deleted = deleted
        self._tableRow = tableRow
        self._token = token
        self._staticcsrf = staticcsrf
        return
