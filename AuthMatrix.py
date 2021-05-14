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
from javax.swing import JComboBox;
from javax.swing import DefaultCellEditor;
from javax.swing import JLabel;
from javax.swing import JFileChooser;
from javax.swing import JPopupMenu;
from javax.swing import JTextField;
from javax.swing import TransferHandler;
from javax.swing import DropMode;
from javax.swing import JSeparator;
from javax.swing import SwingConstants;
from javax.swing import JList
from javax.swing import AbstractCellEditor
from javax.swing import Timer
from java.awt.datatransfer import StringSelection;
from java.awt.datatransfer import DataFlavor;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import TableCellRenderer;
from javax.swing.table import JTableHeader;
from javax.swing.table import TableCellEditor
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
import urllib
import hashlib
import json
import base64
import random
import string


AUTHMATRIX_VERSION = "0.8.2"


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

        # Table of Chain entries (NOTE: must be instantiated before userTable since its referenced)
        self._chainTable = ChainTable(model = ChainTableModel(self))
        chainScrollPane = JScrollPane(self._chainTable)
        self._chainTable.redrawTable()

        # Table of User entries
        self._userTable = UserTable(model = UserTableModel(self))
        roleScrollPane = JScrollPane(self._userTable)
        self._userTable.redrawTable()

        # Table of Request (AKA Message) entries
        self._messageTable = MessageTable(model = MessageTableModel(self))
        messageScrollPane = JScrollPane(self._messageTable)
        self._messageTable.redrawTable()

        # Set Messages to reorderable
        self._messageTable.setDragEnabled(True)
        self._messageTable.setDropMode(DropMode.INSERT_ROWS)
        self._messageTable.setTransferHandler(RowTransferHandler(self._messageTable))                

        # Set Users to reorderable
        self._userTable.setDragEnabled(True)
        self._userTable.setDropMode(DropMode.INSERT_ROWS)
        self._userTable.setTransferHandler(RowTransferHandler(self._userTable))                




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
                        if (type(table) is MessageTable 
                            and column >= selfExtender._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT 
                            or type(table) is UserTable 
                            and column >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT):
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

        class actionToggleEnableUser(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._userTable.getSelectedRows():
                        usersArray = [selfExtender._db.getUserByRow(selfExtender._selectedRow)]
                    else:
                        usersArray = [selfExtender._db.getUserByRow(rowNum) for rowNum in selfExtender._userTable.getSelectedRows()]
                    for userEntry in usersArray:
                        userEntry.toggleEnabled()
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()

        class actionToggleEnableMessage(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messagesArray = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messagesArray = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]
                    for messageEntry in messagesArray:
                        messageEntry.toggleEnabled()
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        class actionToggleEnableChain(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._chainTable.getSelectedRows():
                        chainArray = [selfExtender._db.getChainByRow(selfExtender._selectedRow)]
                    else:
                        chainArray = [selfExtender._db.getChainByRow(rowNum) for rowNum in selfExtender._chainTable.getSelectedRows()]
                    for chainEntry in chainArray:
                        chainEntry.toggleEnabled()
                    selfExtender._selectedColumn = -1
                    selfExtender._chainTable.redrawTable()



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
                    selfExtender._chainTable.redrawTable()

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
                    selfExtender._chainTable.redrawTable()

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

        class actionRemoveColumn(ActionListener):

            def __init__(self, table):
                self._table = table

            def actionPerformed(self,e):
                if selfExtender._selectedColumn >= 0:
                    if self._table == "u":
                        # Delete Role
                        if selfExtender._selectedColumn >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT + selfExtender._db.headerCount + selfExtender._db.arrayOfSVs.size():
                            selfExtender._db.deleteRole(selfExtender._db.getRoleByColumn(
                                selfExtender._selectedColumn, self._table)._index)

                        # Delete SV
                        elif selfExtender._selectedColumn >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT + selfExtender._db.headerCount:
                            selfExtender._db.deleteSV(selfExtender._selectedColumn-(selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT+selfExtender._db.headerCount))

                        # Delete Header
                        elif selfExtender._selectedColumn >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT:
                            selfExtender._db.deleteHeader(selfExtender._selectedColumn-selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT)

                    elif self._table == "m":
                        # Delete Role
                        selfExtender._db.deleteRole(selfExtender._db.getRoleByColumn(
                                selfExtender._selectedColumn, self._table)._index)

                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()
                    selfExtender._messageTable.redrawTable()
                    selfExtender._chainTable.redrawTable()

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

        class actionChangeRegexes(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messages = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messages = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]

                    newRegex,failureRegex = selfExtender.changeRegexPopup()
                    if newRegex:
                        for message in messages:
                            message._regex = newRegex
                            message.setFailureRegex(failureRegex)
                        # Add to list of regexes if its not already there
                        if newRegex not in selfExtender._db.arrayOfRegexes:
                            selfExtender._db.arrayOfRegexes.append(newRegex)

                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()


        class actionChangeDomain(ActionListener):
            def replaceDomain(self, requestResponse, newDomain):
                requestInfo = selfExtender._helpers.analyzeRequest(requestResponse)
                reqBody = requestResponse.getRequest()[requestInfo.getBodyOffset():]            
                newHeaders = ModifyMessage.getNewHeaders(requestInfo, None, ["Host: "+newDomain])
                newreq = selfExtender._helpers.buildHttpMessage(newHeaders, reqBody)
                return newreq

            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messages = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messages = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]
                    
                    # Autofill the service values if they are all the same
                    uniqueServices = [(message._requestResponse.getHttpService().getHost(),
                        message._requestResponse.getHttpService().getPort(),
                        message._requestResponse.getHttpService().getProtocol()) for message in messages]
                    service = None if len(set(uniqueServices)) != 1 else messages[0]._requestResponse.getHttpService()

                    ok, host, port, tls, replaceHost = selfExtender.changeDomainPopup(service)
                    if ok and host:
                        if not port or not port.isdigit():
                            port = 443 if tls else 80
                        for m in messages:
                            if replaceHost:
                                request = self.replaceDomain(m._requestResponse, host)
                            else:
                                request = m._requestResponse.getRequest()
                            # TODO save the Response?
                            m._requestResponse = RequestResponseStored(selfExtender, host, int(port), "https" if tls else "http", request)
                            m.clearResults()
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        class actionSetToggleForRole(ActionListener):
            def __init__(self, enabled):
                self._enabled = enabled

            def actionPerformed(self, e):
                if selfExtender._selectedColumn >= 0:
                    messageIndexes = [selfExtender._db.getMessageByRow(rowNum)._index for rowNum in selfExtender._messageTable.getSelectedRows()]
                    for messageIndex in messageIndexes:
                        roleIndex = selfExtender._db.getRoleByColumn(selfExtender._selectedColumn, "m")._index
                        selfExtender._db.setToggleForRole(messageIndex, roleIndex, self._enabled)
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        # Message Table popups
        messagePopup = JPopupMenu()
        addPopup(self._messageTable,messagePopup)
        toggleEnabled = JMenuItem("Disable/Enable Request(s)")
        toggleEnabled.addActionListener(actionToggleEnableMessage())
        messagePopup.add(toggleEnabled)
        messageRun = JMenuItem("Run Request(s)")
        messageRun.addActionListener(actionRunMessage())
        messagePopup.add(messageRun)
        toggleRegex = JMenuItem("Toggle Regex Mode (Success/Failure)")
        toggleRegex.addActionListener(actionToggleRegex())
        messagePopup.add(toggleRegex)
        changeRegex = JMenuItem("Change Regexes")
        changeRegex.addActionListener(actionChangeRegexes())
        messagePopup.add(changeRegex)
        changeDomain = JMenuItem("Change Target Domain")
        changeDomain.addActionListener(actionChangeDomain())
        messagePopup.add(changeDomain)
        messageRemove = JMenuItem("Remove Request(s)")
        messageRemove.addActionListener(actionRemoveMessage())
        messagePopup.add(messageRemove)
        


        messageHeaderPopup = JPopupMenu()
        addPopup(self._messageTable.getTableHeader(),messageHeaderPopup)
        roleRemoveFromMessageTable = JMenuItem("Remove Role")
        roleRemoveFromMessageTable.addActionListener(actionRemoveColumn("m"))
        messageHeaderPopup.add(roleRemoveFromMessageTable)
        enableToggle = JMenuItem("Bulk Select Checkboxes")
        enableToggle.addActionListener(actionSetToggleForRole(True))
        messageHeaderPopup.add(enableToggle)
        disableToggle = JMenuItem("Bulk Unselect Checkboxes")
        disableToggle.addActionListener(actionSetToggleForRole(False))
        messageHeaderPopup.add(disableToggle)

        # User Table popup
        userPopup = JPopupMenu()
        addPopup(self._userTable,userPopup)
        toggleEnabled = JMenuItem("Disable/Enable User(s)")
        toggleEnabled.addActionListener(actionToggleEnableUser())
        userPopup.add(toggleEnabled)
        userRemove = JMenuItem("Remove Users(s)")
        userRemove.addActionListener(actionRemoveUser())
        userPopup.add(userRemove)


        userHeaderPopup = JPopupMenu()
        addPopup(self._userTable.getTableHeader(),userHeaderPopup)
        removeColumnFromUserTable = JMenuItem("Remove")
        removeColumnFromUserTable.addActionListener(actionRemoveColumn("u"))
        userHeaderPopup.add(removeColumnFromUserTable)

        # Chain Table popup
        chainPopup = JPopupMenu()
        addPopup(self._chainTable,chainPopup)
        toggleEnabled = JMenuItem("Disable/Enable Chain(s)")
        toggleEnabled.addActionListener(actionToggleEnableChain())
        chainPopup.add(toggleEnabled)
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
        self._newHeaderButton = JButton("New Header", actionPerformed=self.newHeaderClick)
        self._newChainButton = JButton("New Chain", actionPerformed=self.newChainClick)
        self._newStaticValueButton =  JButton("New Chain Source", actionPerformed=self.newStaticValueClick)
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
        buttons.add(self._newHeaderButton)
        separator2 = JSeparator(SwingConstants.VERTICAL)
        separator2.setPreferredSize(Dimension(25,0))
        buttons.add(separator2)
        buttons.add(self._newChainButton)
        buttons.add(self._newStaticValueButton)
        separator3 = JSeparator(SwingConstants.VERTICAL)
        separator3.setPreferredSize(Dimension(25,0))
        buttons.add(separator3)
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

        # Handles checkbox, regex, and enabled coloring
        # Must be bellow the customizeUiComponent calls
        self._messageTable.setDefaultRenderer(Boolean, SuccessBooleanRenderer(self._messageTable.getDefaultRenderer(Boolean), self._db))
        self._messageTable.setDefaultRenderer(str, RegexRenderer(self._messageTable.getDefaultRenderer(str), self._db))
        self._userTable.setDefaultRenderer(str, UserEnabledRenderer(self._userTable.getDefaultRenderer(str), self._db))
        self._userTable.setDefaultRenderer(Boolean, UserEnabledRenderer(self._userTable.getDefaultRenderer(Boolean), self._db))
        self._chainTable.setDefaultRenderer(str, ChainEnabledRenderer(self._chainTable.getDefaultRenderer(str), self._db))


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
       
    def highlightTab(self):
        currentPane = self._splitpane
        previousPane = currentPane
        while currentPane and not isinstance(currentPane, JTabbedPane):
            previousPane = currentPane
            currentPane = currentPane.getParent()
        if currentPane:
            index = currentPane.indexOfComponent(previousPane)
            # TODO use old background instead of black (currently doesnt work)
            #oldBackground = currentPane.getBackgroundAt(index)
            currentPane.setBackgroundAt(index,self._db.BURP_ORANGE)

            class setColorBackActionListener(ActionListener):
                def actionPerformed(self, e):
                    currentPane.setBackgroundAt(index,Color.BLACK)
                    
            timer = Timer(5000, setColorBackActionListener())
            timer.setRepeats(False)
            timer.start()



    ##
    ## Creates the sendto tab in other areas of Burp
    ##

    def createMenuItems(self, invocation):

        


        def addRequestsToTab(e):
            for messageInfo in messages:
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                name = str(requestInfo.getMethod()).ljust(8) + requestInfo.getUrl().getPath()
                # Grab regex from response
                regex = "^HTTP/1\\.1 200 OK"
                response = messageInfo.getResponse()
                if response:
                    responseInfo=self._helpers.analyzeResponse(response)
                    if len(responseInfo.getHeaders()):
                        responseCodeHeader = responseInfo.getHeaders()[0]
                        regex = "^"+re.escape(responseCodeHeader)
                # Must create a new RequestResponseStored object since modifying the original messageInfo
                # from its source (such as Repeater) changes this saved object. MessageInfo is a reference, not a copy
                messageIndex = self._db.createNewMessage(RequestResponseStored(self,requestResponse=messageInfo), name, regex)
            self._messageTable.redrawTable()
            self._chainTable.redrawTable()
            self.highlightTab()


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
                self.extender.highlightTab()

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
                for user in self._db.getUsersInOrderByRow():
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

    def getInputUserClick(self, e):
        newUser = JOptionPane.showInputDialog(self._splitpane,"Enter New User:")
        if newUser:
            self._db.getOrCreateUser(newUser)
            self._userTable.redrawTable()
            # redraw Message Table since it adds a new SingleUser Role
            self._messageTable.redrawTable()
            self._chainTable.redrawTable()

    def getInputRoleClick(self, e):
        newRole = JOptionPane.showInputDialog(self._splitpane,"Enter New Role:")
        if newRole:
            self._db.getOrCreateRole(newRole)
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def newChainClick(self,e):
        self._db.createNewChain()
        self._chainTable.redrawTable()

    def newHeaderClick(self, e):
        self._db.addNewHeader()
        self._userTable.redrawTable()

    def newStaticValueClick(self, e):
        newSV = JOptionPane.showInputDialog(self._splitpane,"Enter a label for the new Chain Source:")
        if newSV:
            self._db.addNewSV(newSV)
            self._userTable.redrawTable()
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
            # TODO Potential bug here.  Check if the value being written is 0 before opening
            # TODO add a try catch here?
            jsonValue = self._db.getSaveableJson()
            if jsonValue:
                fileout = open(fileName,'w')
                fileout.write(jsonValue)
                fileout.close()
            else:
                # TODO popup errors instead of prints
                print "Error: Save Failed. JSON empty."
            # TODO currently this will save the config to burp, but not to a specific project
            # Will also need an export and loadFromFile feature if this is ever implemented
            # self._callbacks.saveExtensionSetting("AUTHMATRIX", self._db.getSaveableJson())

    def loadClick(self,e):
        returnVal = self._fc.showOpenDialog(self._splitpane)
        if returnVal == JFileChooser.APPROVE_OPTION:
            f = self._fc.getSelectedFile()
            fileName = f.getPath()
            
            filein = open(fileName,'r')
            jsonText = filein.read()
            filein.close()
            # Check if using on older state file compatible with v0.5.2 or greater
            if not jsonText or jsonText[0] !="{":
                warning = """
                CAUTION: 
    
                Loading a saved configuration prior to v0.6.3 deserializes data into Jython objects. 
                This action may pose a security threat to the application.
                Only proceed when the source and contents of this file is trusted. 
    
                Load Selected File?
                """
                result = JOptionPane.showOptionDialog(self._splitpane, 
                    warning, "Caution", 
                    JOptionPane.YES_NO_OPTION, 
                    JOptionPane.WARNING_MESSAGE, 
                    None, 
                    ["OK", "Cancel"],
                    "OK")

                if result != JOptionPane.YES_OPTION:
                    return
                self._db.loadLegacy(fileName,self)
            else:
                self._db.loadJson(jsonText,self)
                # TODO currently can load exention settings, but this is saved for Burp and not for the Project specifically
                # self._db.loadJson(self._callbacks.loadExtensionSetting("AUTHMATRIX"),self)

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

    def changeRegexPopup(self):
        regexComboBox = JComboBox(self._db.arrayOfRegexes)
        regexComboBox.setEditable(True)
        failureModeCheckbox = JCheckBox()

        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.WEST
        firstline = JPanel()
        firstline.add(JLabel("Select a Regex for all selected Requests:"))
        secondline = JPanel()
        secondline.add(regexComboBox)
        thirdline = JPanel()
        thirdline.add(failureModeCheckbox)
        thirdline.add(JLabel("Regex Detects Unauthorized Requests (Failure Mode)"))


        gbc.gridy = 0
        panel.add(firstline,gbc)
        gbc.gridy = 1
        panel.add(secondline, gbc)
        gbc.gridy = 2
        panel.add(thirdline, gbc)


        result = JOptionPane.showConfirmDialog(self._splitpane, panel, "Select Response Regex", JOptionPane.OK_CANCEL_OPTION)
        value = regexComboBox.getSelectedItem() 
        if result == JOptionPane.CANCEL_OPTION or not value:
            return None, None
        return value, failureModeCheckbox.isSelected()




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
        self._newHeaderButton.setEnabled(not running)
        self._newChainButton.setEnabled(not running)
        self._newStaticValueButton.setEnabled(not running)
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
            messagesThatHaveRun = []
            for message in self._db.getMessagesInOrderByRow():
                # Only run if message is in the selected indexes (NOTE: dependencies will be run even if not selected)
                if message._index in indexes:
                    messagesThatHaveRun = self.runMessageAndDependencies(message._index, messagesThatHaveRun, [])

        except:
            traceback.print_exc(file=self._callbacks.getStderr())
        finally:
            self.lockButtons(False)
            self._db.lock.release()
            self._messageTable.redrawTable()

    def runMessageAndDependencies(self, messageIndex, messagesThatHaveRun, recursionCheckArray):
        messageEntry = self._db.arrayOfMessages[messageIndex]
        updatedMessagesThatHaveRun = messagesThatHaveRun[:]
        updatedRecursionCheckArray = recursionCheckArray[:]

        if messageIndex in updatedRecursionCheckArray:
            print "Error: Recursion detected in message chains: "+"->".join([str(i) for i in updatedRecursionCheckArray])+"->"+str(messageIndex)

        elif (messageIndex not in updatedMessagesThatHaveRun 
            and messageEntry.isEnabled() 
            and messageIndex in self._db.getActiveMessageIndexes()):
                updatedRecursionCheckArray.append(messageIndex)
                for chainIndex in self._db.getActiveChainIndexes():
                    # Run any dependencies first
                    chainEntry = self._db.arrayOfChains[chainIndex]
                    if (messageIndex in chainEntry.getToIDRange() 
                        and chainEntry.isEnabled() 
                        and str(chainEntry._fromID).isdigit() 
                        and int(chainEntry._fromID) >= 0):
                            updatedMessagesThatHaveRun = self.runMessageAndDependencies(int(chainEntry._fromID), updatedMessagesThatHaveRun, updatedRecursionCheckArray)
                self.runMessage(messageIndex)
                # print messageIndex
                updatedMessagesThatHaveRun.append(messageIndex)

        return updatedMessagesThatHaveRun


    def runMessage(self, messageIndex):

        # NOTE: this uses hacky threading tricks for handling timeouts
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


        for userIndex in [userEntry._index for userEntry in self._db.getUsersInOrderByRow()]:
            # Handle cancel button early exit here
            if self._runCancelled:
                return

            userEntry = self._db.arrayOfUsers[userIndex]
            # Only run if the user is enabled
            if userEntry.isEnabled():
                newHeaders = ModifyMessage.getNewHeaders(requestInfo, userEntry._cookies, userEntry._headers)
                newBody = reqBody
    
                # Replace with Chain
                for toValue, chainIndex in userEntry.getChainResultByMessageIndex(messageIndex):
                    # Add transformers
                    chain = self._db.arrayOfChains[chainIndex]
                    toValue = chain.transform(toValue, self._callbacks)       
                    toRegex = chain._toRegex
                    newBody = StringUtil.toBytes(ModifyMessage.chainReplace(toRegex,toValue,[StringUtil.fromBytes(newBody)])[0])
                    newHeaders = ModifyMessage.chainReplace(toRegex,toValue,newHeaders)
    
                # Replace with SV
                # toValue = SV, toRegex = toRegex
                for chain in [self._db.arrayOfChains[i] for i in self._db.getActiveChainIndexes()]:
                    svName = chain.getSVName()
                    # If the Chain Source exists, and this message is affected, and the chain is enabled
                    if svName and messageIndex in chain.getToIDRange() and chain.isEnabled():
                        # get toValue for correct source
                        sourceUser = chain._sourceUser if chain._sourceUser>=0 else userIndex
                        # Check that sourceUser is active
                        if sourceUser in self._db.getActiveUserIndexes():
                            toValue = self._db.getSVByName(svName).getValueForUserIndex(sourceUser)
                            # Add transformers
                            toValue = chain.transform(toValue, self._callbacks)
                            toRegex = chain._toRegex
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
    
                # Create default requestResponse without response
                requestResponse = RequestResponseStored(self, 
                    request=message, 
                    httpService=messageInfo.getHttpService())
    
                if t.isAlive():
                    print "ERROR: Request Timeout for Request #"+str(messageIndex)+" and User #"+str(userIndex)
                elif tempRequestResponse[index]:
                    requestResponse = RequestResponseStored(self,requestResponse=tempRequestResponse[index])
                
                messageEntry.addRunByUserIndex(userIndex, requestResponse)
    
                # Get Chain Result
                response = requestResponse.getResponse()
                if not response:
                    print "ERROR: No HTTP Response for Request #"+str(messageIndex)+" and User #"+str(userIndex)
                else:
                    response = StringUtil.fromBytes(response)
                    for chain in [self._db.arrayOfChains[c] for c in self._db.getActiveChainIndexes()]:
                        # This wont have issues with SV because of the prefix never matching the index
                        if str(chain._fromID) == str(messageIndex) and chain.isEnabled():
                            # If a sourceUser is set, replace for all users' chain results
                            # Else, replace each user's chain results individually
                            replace = True
                            affectedUsers = [userEntry]
                            if str(chain._sourceUser).isdigit() and chain._sourceUser >= 0: # TODO (0.9): why .isdigit()? Can this line just be removed
                                if str(chain._sourceUser) == str(userIndex):
                                    affectedUsers = self._db.getUsersInOrderByRow()
                                else:
                                    replace = False
    
                            if replace:
                                result = ""
                                if chain._fromRegex:
                                    match = re.search(chain._fromRegex, response, re.DOTALL)
                                    if match and len(match.groups()):
                                        result = match.group(1)
                                    
                                for toID in chain.getToIDRange():
                                    for affectedUser in affectedUsers:
                                        affectedUser.addChainResultByMessageIndex(toID, result, chain._index)
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
        for userEntry in self._db.getUsersInOrderByRow():

            ignoreUser = False

            # NOTE: When using failure regex, all users not in a checked role must see that regex

            # if user is not in this role, ignore it
            if not userEntry._roles[roleIndex]:
                ignoreUser = True
            elif not userEntry.isEnabled():
                ignoreUser = True
            else:
                # If user is in any other checked role, then ignore it
                for index in self._db.getActiveRoleIndexes():
                    if not index == roleIndex and userEntry._roles[index]:
                        if index in activeCheckBoxedRoles:
                            ignoreUser = True
                    
            if not ignoreUser:
                if not userEntry._index in messageEntry._userRuns:
                    print ("Unexpected Error: Results not found for Request #"
                        + str(messageEntry._index) + " and User #" + str(userEntry._index))
                    return False
                requestResponse = messageEntry._userRuns[userEntry._index]
                response = requestResponse.getResponse()
                if not response:
                    # No Response: default to failed
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
    def getNewHeaders(requestInfo, newCookieStr, newHeaders):
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
        for newHeader in [x for x in newHeaders if x]:
            replaceIndex = -1
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

    @staticmethod
    def chainReplace(toRegex, toValue, toArray):
        # TODO clean up so that the input is headers+body and its called only once
        isBody = len(toArray)==1
        if toRegex:
            # BUG FIX: Geoff reported that if the regex ends at the newline on the last header,
            # the regex fails.  Hacky solution is to add an extra newlines before the regex search
            # and remove it after.
            to = "\r\n".join(toArray)+"\r\n\r\n"
            match = re.search(toRegex, to, re.DOTALL)
            if match and len(match.groups()):
                ret = (to[0:match.start(1)]+toValue+to[match.end(1):])
                if ret[-4:] == "\r\n\r\n":
                    ret = ret[:-4]
                if isBody:
                    return [ret]
                else:
                    return ret.split("\r\n")
        return toArray

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
        self.STATIC_USER_TABLE_COLUMN_COUNT = 2
        self.STATIC_MESSAGE_TABLE_COLUMN_COUNT = 3
        self.STATIC_CHAIN_TABLE_COLUMN_COUNT = 7
        self.LOAD_TIMEOUT = 10.0
        self.BURP_ORANGE = Color(0xff6633)

        self.lock = Lock()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.arrayOfChains = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0
        self.deletedChainCount = 0
        self.arrayOfSVs = ArrayList()
        self.headerCount = 0
        self.arrayOfRegexes = []


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
                name,
                headers=[""]*self.headerCount))

            # Add SingleUser Role
            self.lock.release()
            singleRoleIndex = self.getOrCreateRole(name, True)
            self.lock.acquire()
            # Check Role for user

            # Add all existing roles as unchecked except the singleUser
            for roleIndex in self.getActiveRoleIndexes():
                prechecked=False
                if roleIndex == singleRoleIndex:
                    prechecked=True
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex,prechecked)

        self.lock.release()
        return userIndex

    # Returns the index of the role, whether its new or not
    def getOrCreateRole(self, role, newSingleUser=False):
        self.lock.acquire()
        roleIndex = -1

        suffix = " (only)"
        name = role+suffix if newSingleUser else role
        if newSingleUser or name.endswith(suffix):
            singleUser = True
        else:
            singleUser = False

        # Check if Role already exists
        for i in self.getActiveRoleIndexes():
            if self.arrayOfRoles[i]._name == name:
                roleIndex = i
        # Add new Role
        if roleIndex < 0:
            roleIndex = self.arrayOfRoles.size()
            newColumn = roleIndex-self.deletedRoleCount

            # Insert column if not singleuser and increment singleuser columns
            if not singleUser:
                newColumn -= self.getActiveSingleUserRoleCount()
                for i in self.getActiveSingleUserRoleIndexes():
                    # NOTE this must be changed if reordering of roles is added
                    curColumn = self.arrayOfRoles[i].getColumn()
                    assert(curColumn >= newColumn)
                    self.arrayOfRoles[i].setColumn(curColumn+1)

            self.arrayOfRoles.add(RoleEntry(roleIndex,
                newColumn, 
                name,
                singleUser=singleUser))

            # Add new role to each existing user as unchecked except the singleUser
            for userIndex in self.getActiveUserIndexes():
                prechecked = False
                if singleUser and self.arrayOfUsers[userIndex]._name == name[:-len(suffix)]:
                    prechecked=True                
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex, prechecked)

            # Add new role to each existing message as unchecked
            for messageIndex in self.getActiveMessageIndexes():
                self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return roleIndex

    # Returns the Row of the new message
    # Unlike Users and Roles, allow duplicate messages
    def createNewMessage(self,messagebuffer,name,regex):
        self.lock.acquire()
        messageIndex = self.arrayOfMessages.size()
        self.arrayOfMessages.add(MessageEntry(messageIndex, messageIndex - self.deletedMessageCount, messagebuffer, name, regex=regex))

        # Add all existing roles as unchecked
        for roleIndex in self.getActiveRoleIndexes():
            self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        # Add regex to array if its new
        if regex and regex not in self.arrayOfRegexes:
            self.arrayOfRegexes.append(regex)


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
                "Example",
                "",
                "StartAfter(.*?)EndAt",
                "",
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
        self.deletedChainCount = 0
        self.arrayOfSVs = ArrayList()
        self.headerCount = 0
        self.arrayOfRegexes = []
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
        self.deletedChainCount = 0 # Updated with chain entries below in arrayOfUsers
        self.arrayOfSVs = ArrayList()
        self.headerCount = 1 # Legacy states had one header only
        self.arrayOfRegexes = []

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
                self.arrayOfUsers.add(UserEntry(
                    int(user._index),
                    int(user._tableRow),
                    name,
                    user._roles,
                    user._deleted,
                    cookies,
                    headers=[header]))

        self.lock.release()

    def loadJson(self, jsonText, extender):
        # NOTE: Weird issue where saving serialized json for configs loaded from old states (pre v0.6.3)
        # doesn't use correct capitalization on bools.
        # This replacement might have weird results, but most are mitigated by using base64 encoding
        jsonFixed = jsonText.replace(": False",": false").replace(": True",": true")

        # Get Rid of comments
        jsonFixed = re.sub(r"[/][*]([^*]|([*][^/]))*[*][/]", "", jsonFixed, 0, re.MULTILINE)

        try:
            stateDict = json.loads(jsonFixed)
        except:
            print jsonFixed
            traceback.print_exc(file=extender._callbacks.getStderr())
            return

        version = stateDict["version"]
        if version > AUTHMATRIX_VERSION:
            print "Invalid Version in State File ("+version+")"
            return

        backupState = self.getSaveableJson()

        self.lock.acquire()

        try:
    
            # NOTE: As of 0.8, If the state file is missing an element, then it assumes it is 
            # the intention of the user to not modify that array, so that just small bits can be updated.
            
            # NOTE: As of 0.8 the deleted counts and header counts are filled in using the values found in each array
    
            # TODO (0.9): every field that has "{int(x" is using an ID in the state that is not obvious to the user
    
            if "arrayOfRoles" in stateDict:
                self.arrayOfRoles = ArrayList()
                self.deletedRoleCount = 0
    
                # (self,index,columnIndex,name,deleted=False,singleUser=False):
                for roleEntry in stateDict["arrayOfRoles"]:
                    deleted = False if "deleted" not in roleEntry else roleEntry["deleted"]
                    if deleted:
                        self.deletedRoleCount += 1
        
                    self.arrayOfRoles.add(RoleEntry(
                        roleEntry["index"],
                        roleEntry["column"],
                        roleEntry["name"],
                        deleted = deleted,
                        singleUser = False if version < "0.7" or "singleUser" not in roleEntry else roleEntry["singleUser"]
                        ))
    
            if "arrayOfUsers" in stateDict:
                self.arrayOfUsers = ArrayList()
                self.deletedUserCount = 0
                self.headerCount = 0
                self.arrayOfSVs = ArrayList()
    
                # NOTE: leaving out chainResults
                # (self, index, tableRow, name, roles = {}, deleted=False, cookies="", headers = [], enabled = True):
                for userEntry in stateDict["arrayOfUsers"]:
                    deleted = False if "deleted" not in userEntry else userEntry["deleted"]
                    if deleted:
                        self.deletedUserCount += 1
    
    
    
                    # Suppport old and new header versions
                    if "headersBase64" in userEntry:
                        headers = [base64.b64decode(x) for x in userEntry["headersBase64"]]
                        # Grab the number of headers. Sanity check will later confirm that each user has the right number of headers
                        if self.headerCount == 0:
                            self.headerCount = len(headers)
                    elif "headerBase64" in userEntry:
                        self.headerCount = 1
                        headers = [base64.b64decode(userEntry["headerBase64"])]
                    else:     
                        headers = [""]*self.headerCount
        
                    
                    self.arrayOfUsers.add(UserEntry(
                        userEntry["index"],
                        userEntry["tableRow"],
                        userEntry["name"],
                        {int(x): userEntry["roles"][x] for x in userEntry["roles"].keys()}, # convert keys to ints
                        deleted = deleted,
                        cookies = "" if "cookiesBase64" not in userEntry else base64.b64decode(userEntry["cookiesBase64"]),
                        headers = headers,
                        enabled = True if "enabled" not in userEntry else userEntry["enabled"]
                        ))
    
                # Update Static Values
                keyword = "arrayOfChainSources" if version >= "0.8" else "arrayOfSVs"
                if keyword in stateDict:
                    for svEntry in stateDict[keyword]:
                        # If the index does not match an active users, do not include it
                        self.arrayOfSVs.add(SVEntry(
                            svEntry["name"],
                            {int(x): svEntry["userValues"][x] for x in svEntry["userValues"].keys() if int(x) in self.getActiveUserIndexes()}, # convert keys to ints
                            ))
    
    
            if "arrayOfMessages" in stateDict:
                self.arrayOfMessages = ArrayList()
                self.deletedMessageCount = 0
                self.arrayOfRegexes = []
    
                # NOTE leaving out roleResults and userRuns (need to convert keys)
                # (self, index, tableRow, requestResponse, name = "", roles = {}, regex = "", deleted = False, failureRegexMode = False, enabled = True):
                for messageEntry in stateDict["arrayOfMessages"]:
                    deleted = False if "deleted" not in messageEntry else messageEntry["deleted"]
                    if deleted:
                        self.deletedMessageCount += 1
        
                    regex = "" if "regexBase64" not in messageEntry else base64.b64decode(messageEntry["regexBase64"]).decode("utf-8")
        
                    if regex and regex not in self.arrayOfRegexes:
                        self.arrayOfRegexes.append(regex)
        
                    requestResponse = None if deleted else RequestResponseStored(
                            extender,
                            messageEntry["host"],
                            messageEntry["port"],
                            messageEntry["protocol"],
                            StringUtil.toBytes((base64.b64decode(messageEntry["requestBase64"])).decode("utf-8")))
        
                    self.arrayOfMessages.add(MessageEntry(
                        messageEntry["index"],
                        messageEntry["tableRow"],
                        requestResponse,
                        messageEntry["name"], 
                        {int(x): messageEntry["roles"][x] for x in messageEntry["roles"].keys()}, # convert keys to ints
                        regex = regex, 
                        deleted = deleted, 
                        failureRegexMode = False if "failureRegexMode" not in messageEntry else messageEntry["failureRegexMode"],
                        enabled = True if "enabled" not in messageEntry else messageEntry["enabled"]
                        ))
    
    
            if "arrayOfChains" in stateDict:
                self.arrayOfChains = ArrayList()
                self.deletedChainCount = 0
    
                # NOTE: leaving out fromStart, fromEnd, toStart, toEnd
                for chainEntry in stateDict["arrayOfChains"]:
                    deleted = False if "deleted" not in chainEntry else chainEntry["deleted"]
                    if deleted:
                        self.deletedChainCount += 1
        
                    self.arrayOfChains.add(ChainEntry(
                        chainEntry["index"],
                        chainEntry["tableRow"],
                        name = "" if "name" not in chainEntry else chainEntry["name"],
                        fromID = "" if "fromID" not in chainEntry else chainEntry["fromID"],
                        fromRegex = "" if "fromRegexBase64" not in chainEntry else base64.b64decode(chainEntry["fromRegexBase64"]).decode("utf-8"),
                        toID = "" if "toID" not in chainEntry else chainEntry["toID"],
                        toRegex = "" if "toRegexBase64" not in chainEntry else base64.b64decode(chainEntry["toRegexBase64"]).decode("utf-8"),
                        deleted = deleted,
                        sourceUser = -1 if "sourceUser" not in chainEntry else chainEntry["sourceUser"],
                        enabled = True if "enabled" not in chainEntry else chainEntry["enabled"],
                        transformers = [] if "transformers" not in chainEntry else chainEntry["transformers"]
                        ))
        
        except:
            self.lock.release()
            print "Corrupt State File: Reverting back to original. (See stderr for more detail)"
            traceback.print_exc(file=extender._callbacks.getStderr())
            self.loadJson(backupState,extender)
            return

        self.lock.release()

        # Sanity checks
        sanityResult = self.sanityCheck(extender)
        if sanityResult:
            print "Error parsing state file: "+sanityResult
            # Revert to the backup state
            self.loadJson(backupState,extender)



    def sanityCheck(self, extender):
        try:
            # Returns an error string if the DB is in a corrupt state, else returns None
            userIndexes = self.getActiveUserIndexes() 
            roleIndexes = self.getActiveRoleIndexes()
            messageIndexes = self.getActiveMessageIndexes()
            chainIndexes = self.getActiveChainIndexes()
    
            # Index Checks
            for indexes, currentArray, deletedCount in [
                (userIndexes, self.arrayOfUsers, self.deletedUserCount),
                (roleIndexes, self.arrayOfRoles, self.deletedRoleCount),
                (messageIndexes, self.arrayOfMessages, self.deletedMessageCount),
                (chainIndexes, self.arrayOfChains, self.deletedChainCount)]:
                    # Check that indexes are all unique
                    if len(indexes) > len(set(indexes)):
                        return "Not All Indexes are Unique."
                    # Check that the DB array has the correct number of items
                    if len(currentArray) != len(indexes) + deletedCount:
                        return "Array found with incorrect number of items."
                    for currentIndex in indexes:
                        if currentIndex < 0:
                            return "Negative Index Found."
                        # Check that all index values are below the length of active+deleted
                        if currentIndex >= len(indexes)+deletedCount:
                            return "Index Higher than Total Active + Deleted."
                        # Check that the indexes within the array match the index of the Entry
                        if currentIndex != currentArray[currentIndex]._index:
                            return "Entries in the State File Arrays must be in order by index"
    
            # Row Checks
            for indexes, currentArray in [             
                (userIndexes, self.arrayOfUsers),
                (messageIndexes, self.arrayOfMessages),
                (chainIndexes, self.arrayOfChains)]:
                    rowList = [currentArray[currentIndex].getTableRow() for currentIndex in indexes]
                    # Check that the rows for a given table are all unique
                    if len(rowList) > len(set(rowList)):
                        return "Not all rows for a given table are unique."
                    for row in rowList:
                        # Check that rows are within appropriate bounds
                        if row >= len(indexes) or row <0:
                            return "Row out of bounds."
    
            # Column Checks
            columnList = [self.arrayOfRoles[currentIndex].getColumn() for currentIndex in roleIndexes]
            if len(columnList) > len(set(columnList)):
                return "Not all columns for Roles array are unique."
            for column in columnList:
                if column < 0 or column >= len(roleIndexes):
                    return "Column out of bounds."
    
            # Custom Headers checks
            for userIndex in userIndexes:
                if len(self.arrayOfUsers[userIndex]._headers) != self.headerCount:
                    return "Incorrect Number of Headers for a User.  Must be "+str(self.headerCount)
    
            # Role Assignment Checks
            for indexes, currentArray in [             
                (userIndexes, self.arrayOfUsers),
                (messageIndexes, self.arrayOfMessages)]:
                    for index in indexes:
                        # Check that all keys are unique (might be redundant)
                        roleKeys = currentArray[index]._roles.keys()
                        if len(roleKeys) > len(set(roleKeys)):
                            return "Duplicate Keys on Roles Map"
                        # Check that all active roles are covered in that items map
                        for roleIndex in roleIndexes:
                            if roleIndex not in roleKeys:
                                return "Missing a Role Value in a Message or User"

            # NOTE: Skipping Static Value check because a missing SV is handled gracefully

            # TODO (0.9): check fromID and sourceUser in Chain

        except:
            traceback.print_exc(file=extender._callbacks.getStderr())
            return "Unidentified"
        return None


    def getSaveableJson(self):
        stateDict = {"version":AUTHMATRIX_VERSION}

        stateDict["arrayOfRoles"] = []
        for roleEntry in self.arrayOfRoles:
            deleted = roleEntry._deleted
            stateDict["arrayOfRoles"].append({
                    "index":roleEntry._index,
                    "name":roleEntry._name if not deleted else None,
                    "deleted":deleted,
                    "column":roleEntry._column if not deleted else None,
                    "singleUser":roleEntry._singleUser if not deleted else None
                })

        stateDict["arrayOfUsers"] = []
        for userEntry in self.arrayOfUsers:
            deleted = userEntry._deleted
            stateDict["arrayOfUsers"].append({
                    "index":userEntry._index,
                    "name":userEntry._name if not deleted else None,
                    "roles":userEntry._roles if not deleted else {},
                    "deleted":deleted,
                    "enabled":userEntry._enabled,
                    "tableRow":userEntry._tableRow if not deleted else None,
                    "cookiesBase64":base64.b64encode(userEntry._cookies.encode("utf-8")) if userEntry._cookies and not deleted else "",
                    "headersBase64":[base64.b64encode(x.encode("utf-8")) if x else "" for x in userEntry._headers] if not deleted else [],
                    "chainResults":userEntry._chainResults if not deleted else {}
                })

        stateDict["arrayOfMessages"] = []
        for messageEntry in self.arrayOfMessages:
            deleted = messageEntry._deleted
            stateDict["arrayOfMessages"].append({
                    "index":messageEntry._index, 
                    "tableRow":messageEntry._tableRow if not deleted else None,
                    "requestBase64":base64.b64encode(StringUtil.fromBytes(messageEntry._requestResponse.getRequest()).encode("utf-8")) if not deleted else None,
                    "host":messageEntry._requestResponse.getHttpService().getHost() if not deleted else None,
                    "port":messageEntry._requestResponse.getHttpService().getPort() if not deleted else None,
                    "protocol":messageEntry._requestResponse.getHttpService().getProtocol() if not deleted else None,
                    "name":messageEntry._name if not deleted else None, 
                    "roles":messageEntry._roles if not deleted else {}, 
                    "regexBase64":base64.b64encode(messageEntry._regex.encode("utf-8")) if messageEntry._regex and not deleted else "", 
                    "deleted":deleted,
                    "enabled":messageEntry._enabled,
                    "failureRegexMode":messageEntry._failureRegexMode if not deleted else None,
                    "runBase64ForUserID":{int(x): {
                        "request": None if not messageEntry._userRuns[x] or not messageEntry._userRuns[x].getRequest() else base64.b64encode(StringUtil.fromBytes(messageEntry._userRuns[x].getRequest()).encode("utf-8")),
                        "response": None if not messageEntry._userRuns[x] or not messageEntry._userRuns[x].getResponse() else base64.b64encode(StringUtil.fromBytes(messageEntry._userRuns[x].getResponse()).encode("utf-8"))}
                        for x in messageEntry._userRuns.keys()} if not deleted else {},
                    "runResultForRoleID":messageEntry._roleResults if not deleted else {}
                })

        stateDict["arrayOfChains"] = []
        for chainEntry in self.arrayOfChains:
            deleted = chainEntry._deleted
            stateDict["arrayOfChains"].append({
                    "index":chainEntry._index,
                    "fromID":chainEntry._fromID if not deleted else None,
                    "fromRegexBase64":base64.b64encode(chainEntry._fromRegex.encode("utf-8")) if chainEntry._fromRegex and not deleted else "",
                    "toID":chainEntry._toID if not deleted else None,
                    "toRegexBase64":base64.b64encode(chainEntry._toRegex.encode("utf-8")) if chainEntry._toRegex and not deleted else "",
                    "deleted":deleted,
                    "enabled":chainEntry._enabled,
                    "tableRow":chainEntry._tableRow if not deleted else None,
                    "name":chainEntry._name if not deleted else None,
                    "sourceUser":chainEntry._sourceUser if not deleted else None,
                    "fromStart":chainEntry._fromStart if not deleted else None,
                    "fromEnd":chainEntry._fromEnd if not deleted else None,
                    "toStart":chainEntry._toStart if not deleted else None,
                    "toEnd":chainEntry._toEnd if not deleted else None,
                    "transformers":chainEntry._transformers if not deleted else []
                })

        stateDict["arrayOfChainSources"] = []
        for SVEntry in self.arrayOfSVs:
            stateDict["arrayOfChainSources"].append({
                "name":SVEntry._name,
                "userValues":SVEntry._userValues
                })

        # BUG: this is not using the correct capitalization on booleans after loading legacy states
        return json.dumps(stateDict)

    def getActiveUserIndexes(self):
        return [x._index for x in self.arrayOfUsers if not x.isDeleted()]

    def getActiveRoleIndexes(self):
        return [x._index for x in self.arrayOfRoles if not x.isDeleted()]

    def getActiveSingleUserRoleIndexes(self):
        return [x._index for x in self.arrayOfRoles if x.isSingleUser() and not x.isDeleted()]

    def getActiveMessageIndexes(self):
        return [x._index for x in self.arrayOfMessages if not x.isDeleted()]

    def getActiveChainIndexes(self):
        return [x._index for x in self.arrayOfChains if not x.isDeleted()]        

    def getActiveUserCount(self):
        ret = self.arrayOfUsers.size()-self.deletedUserCount
        assert(ret == len(self.getActiveUserIndexes()))
        return ret

    def getActiveRoleCount(self):
        ret = self.arrayOfRoles.size()-self.deletedRoleCount
        assert(ret == len(self.getActiveRoleIndexes()))
        return ret

    def getActiveMessageCount(self):
        ret = self.arrayOfMessages.size()-self.deletedMessageCount
        assert(ret == len(self.getActiveMessageIndexes()))
        return ret


    def getActiveSingleUserRoleCount(self):
        return len(self.getActiveSingleUserRoleIndexes())


    def getActiveChainCount(self):
        return self.arrayOfChains.size()-self.deletedChainCount    

    def getMessageByRow(self, row):
        for messageEntry in [self.arrayOfMessages[i] for i in self.getActiveMessageIndexes()]:
            if messageEntry.getTableRow() == row:
                return messageEntry

    def getUserByRow(self, row):
        for userEntry in [self.arrayOfUsers[i] for i in self.getActiveUserIndexes()]:
            if userEntry.getTableRow() == row:
                return userEntry

    def getRoleByColumn(self,column, table):
        startingIndex = self.STATIC_MESSAGE_TABLE_COLUMN_COUNT if table == "m" else self.STATIC_USER_TABLE_COLUMN_COUNT+self.headerCount+self.arrayOfSVs.size()
        for roleEntry in [self.arrayOfRoles[i] for i in self.getActiveRoleIndexes()]:
            if roleEntry.getColumn()+startingIndex == column:
                return roleEntry

    def getChainByRow(self, row):
        for chainEntry in [self.arrayOfChains[i] for i in self.getActiveChainIndexes()]:
            if chainEntry.getTableRow() == row:
                return chainEntry

    def deleteUser(self,userIndex):
        self.lock.acquire()
        userEntry = self.arrayOfUsers[userIndex]
        if userEntry:
            userEntry.setDeleted()
            self.deletedUserCount += 1

            previousRow = userEntry.getTableRow()
            for user in [self.arrayOfUsers[i] for i in self.getActiveUserIndexes()]:
                if user.getTableRow()>previousRow:
                    user.setTableRow(user.getTableRow()-1)

            # TODO maybe delete SingleUser role too (though it might be worth leaving if the user has boxes checked)

        self.lock.release()

    def deleteRole(self,roleIndex):
        self.lock.acquire()
        roleEntry = self.arrayOfRoles[roleIndex]
        if roleEntry:
            roleEntry.setDeleted()
            self.deletedRoleCount += 1

            previousColumn = roleEntry.getColumn()
            for role in [self.arrayOfRoles[i] for i in self.getActiveRoleIndexes()]:
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
            for message in [self.arrayOfMessages[i] for i in self.getActiveMessageIndexes()]:
                if message.getTableRow()>previousRow:
                    message.setTableRow(message.getTableRow()-1)

        self.lock.release()

    def setToggleForRole(self, messageIndex, roleIndex, enabled):
        self.lock.acquire()
        messageEntry = self.arrayOfMessages[messageIndex]
        messageEntry.setToggleForRoleByIndex(roleIndex, enabled)
        self.lock.release()

    def deleteChain(self,chainIndex):
        self.lock.acquire()
        chainEntry = self.arrayOfChains[chainIndex]
        if chainEntry:
            chainEntry.setDeleted()
            self.deletedChainCount += 1

            previousRow = chainEntry.getTableRow()
            for chain in [self.arrayOfChains[i] for i in self.getActiveChainIndexes()]:
                if chain.getTableRow()>previousRow:
                    chain.setTableRow(chain.getTableRow()-1)

        self.lock.release()            

    def getMessagesInOrderByRow(self):
        messages = []
        for i in range(self.getActiveMessageCount()):
            messages.append(self.getMessageByRow(i))
        return messages

    def getUsersInOrderByRow(self):
        users = []
        for i in range(self.getActiveUserCount()):
            users.append(self.getUserByRow(i))
        return users

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

    def moveUserToRow(self, fromRow, toRow):
        self.lock.acquire()
        users = self.getUsersInOrderByRow()
        if fromRow > toRow:
            users[fromRow].setTableRow(toRow)
            for i in range(toRow,fromRow):
                users[i].setTableRow(i+1)

        elif toRow > fromRow:
            users[fromRow].setTableRow(toRow-1)
            for i in range(fromRow+1,toRow):
                users[i].setTableRow(i-1)
        self.lock.release()


    def clearAllChainResults(self):
        for i in self.getActiveUserIndexes():
            self.arrayOfUsers[i].clearChainResults()

    def getUserByName(self, name):
        for i in self.getActiveUserIndexes():
            if self.arrayOfUsers[i]._name == name:
                return self.arrayOfUsers[i]

    def getRoleByName(self, name):
        for i in self.getActiveRoleIndexes():
            if self.arrayOfRoles[i]._name == name:
                return self.arrayOfRoles[i]

    def addNewSV(self, name):
        if not self.getSVByName(name):
            self.lock.acquire()
            newSVEntry = SVEntry(name)
            self.arrayOfSVs.add(newSVEntry)
            self.lock.release()
            return newSVEntry

    def getSVByName(self, name):
        for sv in self.arrayOfSVs:
            if sv._name == name:
                return sv
        return None

    def deleteSV(self, index):
        if index >=0 and index<self.arrayOfSVs.size():
            self.lock.acquire()
            self.arrayOfSVs.remove(self.arrayOfSVs[index])
            self.lock.release()

    def addNewHeader(self):
        self.headerCount += 1
        for userEntry in [self.arrayOfUsers[i] for i in self.getActiveUserIndexes()]:
            userEntry._headers.append("")
            assert(len(userEntry._headers)==self.headerCount)

    def deleteHeader(self,index):
        if index >=0 and index <self.headerCount:
            self.headerCount -= 1
            for userEntry in [self.arrayOfUsers[i] for i in self.getActiveUserIndexes()]:
                userEntry._headers.pop(index)
                assert(len(userEntry._headers)==self.headerCount)
            return True
        return False


##
## Tables and Table Models  
##
    
class UserTableModel(AbstractTableModel):

    def __init__(self, extender):
        self._extender = extender
        self._db = extender._db

    def getRowCount(self):
        return self._db.getActiveUserCount()

    def getColumnCount(self):
        return (self._db.STATIC_USER_TABLE_COLUMN_COUNT
            +self._db.headerCount
            +self._db.arrayOfSVs.size()
            +self._db.getActiveRoleCount()
            -self._db.getActiveSingleUserRoleCount())
        
    def getColumnName(self, columnIndex):
        headerIndex = columnIndex-self._db.STATIC_USER_TABLE_COLUMN_COUNT
        svIndex = headerIndex - self._db.headerCount
        if columnIndex == 0:
            return "User Name"
        elif columnIndex == 1:
            return "Cookies"
        elif headerIndex >=0 and headerIndex<self._db.headerCount:
            return "HTTP Header"
        elif svIndex >= 0 and svIndex < self._db.arrayOfSVs.size():
            return self._db.arrayOfSVs[svIndex]._name
        else:
            roleEntry = self._db.getRoleByColumn(columnIndex, 'u')
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        userEntry = self._db.getUserByRow(rowIndex)
        headerIndex = columnIndex-self._db.STATIC_USER_TABLE_COLUMN_COUNT
        svIndex = headerIndex - self._db.headerCount
        if userEntry:
            if columnIndex == 0:
                return userEntry._name
            elif columnIndex == 1:
                return userEntry._cookies
            elif headerIndex >=0 and headerIndex<self._db.headerCount:
                return userEntry._headers[headerIndex]
            elif svIndex >= 0 and svIndex < self._db.arrayOfSVs.size():
                return self._db.arrayOfSVs[svIndex].getValueForUserIndex(userEntry._index)
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
        headerIndex = col-self._db.STATIC_USER_TABLE_COLUMN_COUNT
        svIndex = headerIndex - self._db.headerCount
        if userEntry:
            if col == 0:
                # Verify user name does not already exist
                if not self._db.getUserByName(val):
                    # Rename SingleUser role too
                    roleEntry = self._db.getRoleByName(userEntry._name+" (only)")
                    if roleEntry:
                        roleEntry._name = val+" (only)"
                    userEntry._name = val
            elif col == 1:
                userEntry._cookies = val
            elif headerIndex >=0 and headerIndex<self._db.headerCount:
                userEntry._headers[headerIndex] = val
            elif svIndex >= 0 and svIndex < self._db.arrayOfSVs.size():
                self._db.arrayOfSVs[svIndex].setValueForUserIndex(userEntry._index, val)
            else:
                roleIndex = self._db.getRoleByColumn(col, 'u')._index
                userEntry.addRoleByIndex(roleIndex, val)

        self.fireTableCellUpdated(row,col)
        # Refresh dropdown menu for Chains and SingleUser Role names for Messages
        self._extender._chainTable.redrawTable()
        self._extender._messageTable.redrawTable()

    # Set checkboxes and role editable
    def isCellEditable(self, row, col):
        return True
        
    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex < self._db.STATIC_USER_TABLE_COLUMN_COUNT+self._db.headerCount+self._db.arrayOfSVs.size():
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
        
        # User Name
        self.getColumnModel().getColumn(0).setMinWidth(150);
        self.getColumnModel().getColumn(0).setMaxWidth(1000);

        # Cookie
        self.getColumnModel().getColumn(1).setMinWidth(150);
        self.getColumnModel().getColumn(1).setMaxWidth(1500);

        self.getTableHeader().getDefaultRenderer().setHorizontalAlignment(JLabel.CENTER)


class MessageTableModel(AbstractTableModel):

    def __init__(self, extender):
        self._extender = extender
        self._db = extender._db

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
                # TODO (0.9): Maybe show the index here to help with constructing state files?
                #return roleEntry._name+" (#"+str(roleEntry._index)+")"
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
                # Add this value to the array
                if val and val not in self._db.arrayOfRegexes:
                    self._db.arrayOfRegexes.append(val)
                # TODO (0.9): Remove unused Regexes from that list
            else:
                roleIndex = self._db.getRoleByColumn(col, 'm')._index
                messageEntry.addRoleByIndex(roleIndex,val)
    
            self.fireTableCellUpdated(row,col)
            # Update the checkbox result colors since there was a change
            if col >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
                messageEntry.clearResults()
                for i in range(self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT, self.getColumnCount()):
                    self.fireTableCellUpdated(row,i)
                # Backup option
                # Update entire table since it affects color
                # self.fireTableDataChanged()

            # Refresh table so that combobox updates
            self._extender._messageTable.redrawTable()


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

    def __init__(self, model):
        self.setModel(model)
        self._extender = model._extender
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

        for userEntry in self.getModel()._db.getUsersInOrderByRow():
            if userEntry._index in selectedMessage._userRuns.keys():
                tabname = str(userEntry._name)
                self._extender._tabs.addTab(tabname,self.createRequestTabs(selectedMessage._userRuns[userEntry._index]))
                                
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
        if not original:
            requestTabs.setSelectedIndex(1)

        if original and index>=0:
            self._viewerMap[index] = requestViewer

        return requestTabs

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()

        db = self.getModel()._db

        # Regex comboboxes
        regexComboBox = JComboBox(db.arrayOfRegexes)
        regexComboBox.setEditable(True)
        regexComboBoxEditor = DefaultCellEditor(regexComboBox)
        self.getColumnModel().getColumn(2).setCellEditor(regexComboBoxEditor)



        # Resize
        self.getColumnModel().getColumn(0).setMinWidth(30);
        self.getColumnModel().getColumn(0).setMaxWidth(45);
        self.getColumnModel().getColumn(1).setMinWidth(300);
        self.getColumnModel().getColumn(2).setMinWidth(150);

    def updateMessages(self):
        # For now it sounds like this does not need to be locked, since its only manual operations
        for messageIndex in self._viewerMap:
            requestViewer = self._viewerMap[messageIndex]
            if requestViewer and requestViewer.isMessageModified():
                messageEntry = self.getModel()._db.arrayOfMessages[messageIndex]
                newMessage = requestViewer.getMessage()
                # TODO save the response too? Downside is that the original may not match the response anymore
                messageEntry._requestResponse = RequestResponseStored(self._extender, 
                    request=newMessage, 
                    httpService=messageEntry._requestResponse.getHttpService())                
        self._viewerMap = {}




###
### Chain Tables
###

class ChainTableModel(AbstractTableModel):

    def __init__(self, extender):
        self._extender = extender
        self._db = extender._db
        self.chainFromDefault = "All Users (Default)"
        self.requestPrefix = "Request: "
        self.svPrefix = "SV_"
        self.destPrefix = "Request(s): "

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
            return "Chain Name"
        elif columnIndex == 1:
            return "Source"
        elif columnIndex == 2:
            return "Regex - Extract from HTTP Response"
        elif columnIndex == 3:
            return "Destination(s)"
        elif columnIndex == 4:
            return "Regex - Replace into HTTP Request"
        elif columnIndex == 5:
            return "Use Values From:"
        elif columnIndex == 6:
            return "Transformers"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if self.getColumnCount() == 1:
            return ""

        chainEntry = self._db.getChainByRow(rowIndex)
        if chainEntry:
            if columnIndex == 0:
                return chainEntry._name
            elif columnIndex == 1:
                if chainEntry._fromID.isdigit() and int(chainEntry._fromID) in self._db.getActiveMessageIndexes():
                    return self.requestPrefix+chainEntry._fromID
                elif chainEntry._fromID.startswith(self.svPrefix):
                    # If it's a string, check if its a SV
                    svEntry = self._db.getSVByName(chainEntry._fromID[len(self.svPrefix):])
                    if svEntry:
                        return svEntry._name
                    else:
                        return ""
                else:
                    return ""
            elif columnIndex == 2:
                return chainEntry._fromRegex
            elif columnIndex == 3:
                return "" if not chainEntry._toID else self.destPrefix+chainEntry._toID
            elif columnIndex == 4:
                return chainEntry._toRegex
            elif columnIndex == 5:
                if chainEntry._sourceUser in self._db.getActiveUserIndexes():
                    return self._db.arrayOfUsers[chainEntry._sourceUser]._name
                elif chainEntry._sourceUser == -1:
                    return self.chainFromDefault
                else:
                    return ""
            elif columnIndex == 6:
                ret = "x"
                for transformer in chainEntry._transformers:
                    ret = transformer+"("+ret+")"
                return "" if ret == "x" else ret
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
                chainEntry._name = val
            elif col == 1:
                if val and self.requestPrefix in val and val[len(self.requestPrefix):].isdigit():
                    chainEntry._fromID = val[len(self.requestPrefix):]
                else:
                    # If it's a string, check if its a SV
                    svEntry = self._db.getSVByName(val)
                    if svEntry:
                        chainEntry._fromID = self.svPrefix+svEntry._name
                        # Clear fromRegex since its unused
                        chainEntry._fromRegex = ""
                        self.fireTableCellUpdated(row,col+1)
                    else:
                        chainEntry._fromID = ""
            elif col == 2:
                chainEntry._fromRegex = val
            elif col == 3:
                chainEntry._toID = val
            elif col == 4:
                chainEntry._toRegex = val
            elif col == 5:
                user = self._db.getUserByName(val)
                if user:
                    chainEntry._sourceUser = user._index
                else:
                    chainEntry._sourceUser = -1
            elif col == 6:
                if val == "(clear)":
                    chainEntry.clearTransformers()
                else:
                    chainEntry.addTransformer(val)

            self.fireTableCellUpdated(row,col)


    def isCellEditable(self, row, col):
        if col >= 0:
            # Disable Regex when SV
            if col == 2 and self._db.getChainByRow(row).getSVName():
                return False
            else:
                return True
        return False

    def getColumnClass(self, columnIndex):
        return str
        


class ChainTable(JTable):

    def __init__(self, model):
        self.setModel(model)
        return

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()
        



        if self.getModel().getColumnCount() > 1:

            db = self.getModel()._db

            # Chain Use Value From comboboxes
            users = [self.getModel().chainFromDefault]+[userEntry._name for userEntry in db.getUsersInOrderByRow()]
            usersComboBox = JComboBox(users)
            usersComboBoxEditor = DefaultCellEditor(usersComboBox)
            self.getColumnModel().getColumn(5).setCellEditor(usersComboBoxEditor)

            # Tranformers Combobox
            transformers = ["(clear)"]+ChainEntry.TransformerList
            transformerComboBox = JComboBox(transformers)
            transformerComboBoxEditor = DefaultCellEditor(transformerComboBox)
            self.getColumnModel().getColumn(6).setCellEditor(transformerComboBoxEditor)

            # Source ID comboboxes
            sources = [sv._name for sv in db.arrayOfSVs] + [self.getModel().requestPrefix+str(x) for x in db.getActiveMessageIndexes()]
            sourcesComboBox = JComboBox(sources)
            sourcesComboBoxEditor = DefaultCellEditor(sourcesComboBox)
            self.getColumnModel().getColumn(1).setCellEditor(sourcesComboBoxEditor)


            destPrefix = self.getModel().destPrefix
            # Popup editor for DEST IDs
            class DestinationCellEditor(AbstractCellEditor, TableCellEditor, ActionListener):
                # https://stackoverflow.com/questions/14153544/jtable-how-to-update-cell-using-custom-editor-by-pop-up-input-dialog-box
                self.scrollablePane = JScrollPane()
                self.destList = JList()
                self.button = JButton()
                self.oldVal = ""

                def actionPerformed(self,e):
                    JOptionPane.showMessageDialog(self.button,self.scrollablePane,"Select All Request IDs",JOptionPane.PLAIN_MESSAGE)                    
                    self.fireEditingStopped()

                def getTableCellEditorComponent(self,table,value,isSelected,rowIndex,vColIndex):
                    self.oldVal = value if destPrefix not in value else value[len(destPrefix):]
                    dests = db.getActiveMessageIndexes()
                    if dests:
                        self.destList = JList(dests)
                        self.destList.setVisibleRowCount(10)
                        self.scrollablePane = JScrollPane(self.destList)
    
                        self.button = JButton()
                        self.button.setBorderPainted(False)
                        self.button.setOpaque(False)
                        self.button.setContentAreaFilled(False)
                        
                        self.button.addActionListener(self)
                        return self.button
                    

                def getCellEditorValue(self):
                    newValues = self.destList.getSelectedValuesList()
                    if not newValues:
                        return self.oldVal
                    return self.listToRanges(newValues)

                # Convert a list of ints into a range string
                def listToRanges(self, intList):
                    ret = []
                    for val in sorted(intList):
                        if not ret or ret[-1][-1]+1 != val:
                            ret.append([val])
                        else:
                            ret[-1].append(val)
                    return ",".join([str(x[0]) if len(x)==1 else str(x[0])+"-"+str(x[-1]) for x in ret])

            self.getColumnModel().getColumn(3).setCellEditor(DestinationCellEditor())

            # Resize
            self.getColumnModel().getColumn(0).setMinWidth(180);
            self.getColumnModel().getColumn(0).setMaxWidth(300);
            self.getColumnModel().getColumn(1).setMinWidth(115);
            self.getColumnModel().getColumn(1).setMaxWidth(175);        
            self.getColumnModel().getColumn(2).setMinWidth(180);
            self.getColumnModel().getColumn(3).setMinWidth(160);
            self.getColumnModel().getColumn(3).setMaxWidth(320);        
            self.getColumnModel().getColumn(4).setMinWidth(180);
            self.getColumnModel().getColumn(5).setMinWidth(150);
            self.getColumnModel().getColumn(5).setMaxWidth(270); 
            self.getColumnModel().getColumn(6).setMinWidth(100);



# For color-coding checkboxes in the message table
# Also Grey when not enabled
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
                if messageEntry.isEnabled():
                    roleEntry = self._db.getRoleByColumn(column, 'm')
                    if roleEntry:
                        roleIndex = roleEntry._index
                        if not roleIndex in messageEntry._roleResults:
                            if isSelected:
                                cell.setBackground(table.getSelectionBackground())
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
                else:
                    if isSelected:
                        cell.setBackground(Color(0xD1,0xB5,0xA3))
                    else:
                        cell.setBackground(Color.GRAY)

        return cell
      

# For color-coding successregex in the message table
# Also Grey when not enabled
class RegexRenderer(JLabel, TableCellRenderer):

    def __init__(self, defaultCellRender, db):
        self._defaultCellRender = defaultCellRender
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Regex color
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        messageEntry = self._db.getMessageByRow(row)

        if column == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
            if messageEntry:
                if messageEntry.isFailureRegex():
                    # Set Grey if failure mode
                    if isSelected:
                        cell.setBackground(Color(0xD1,0xB5,0xA3))
                    else:
                        cell.setBackground(Color(0x99,0x99,0xCC))
                else:
                    if isSelected:
                        cell.setBackground(table.getSelectionBackground())
                    else:
                        cell.setBackground(table.getBackground())
        else:
            if isSelected:
                cell.setBackground(table.getSelectionBackground())
            else:
                cell.setBackground(table.getBackground())
        # Set grey if disabled
        if messageEntry and not messageEntry.isEnabled():
            if isSelected:
                cell.setBackground(Color(0xD1,0xB5,0xA3))
            else:
                cell.setBackground(Color.GRAY)
        return cell

# Default Renderer checking User Table for Enabled
class UserEnabledRenderer(TableCellRenderer):
    def __init__(self, defaultCellRender, db):
        self._defaultCellRender = defaultCellRender
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Regex color
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        userEntry = self._db.getUserByRow(row)
        if userEntry and not userEntry.isEnabled():
            if isSelected:
                cell.setBackground(Color(0xD1,0xB5,0xA3))
            else:
                cell.setBackground(Color.GRAY)
        elif isSelected:
            cell.setBackground(table.getSelectionBackground())
        else:
            cell.setBackground(table.getBackground())
        return cell

# TODO (0.9): combine these classes
# Default Renderer checking Chain Table for Enabled
class ChainEnabledRenderer(TableCellRenderer):
    def __init__(self, defaultCellRender, db):
        self._defaultCellRender = defaultCellRender
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Regex color
        cell = self._defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        chainEntry = self._db.getChainByRow(row)
        if chainEntry and not chainEntry.isEnabled():
            if isSelected:
                cell.setBackground(Color(0xD1,0xB5,0xA3))
            else:
                cell.setBackground(Color.GRAY)
        elif isSelected:
            cell.setBackground(table.getSelectionBackground())
        else:
            cell.setBackground(table.getBackground())
        return cell



##
## Classes for Messages, Roles, and Users
##

class MessageEntry:

    def __init__(self, index, tableRow, requestResponse, name = "", roles = {}, regex = "", deleted = False, failureRegexMode = False, enabled = True):
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
        self._enabled = enabled
        return

    # Role are the index of the db Role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self,roleIndex,enabled=False):
        self._roles[roleIndex] = enabled;

    def setToggleForRoleByIndex(self, roleIndex, enabled):
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

    def isEnabled(self):
        return self._enabled

    def toggleEnabled(self):
        self._enabled = not self._enabled


class UserEntry:

    def __init__(self, index, tableRow, name, roles = {}, deleted=False, cookies="", headers = [], enabled = True):
        self._index = index
        self._name = name
        self._roles = roles.copy()
        self._deleted = deleted
        self._tableRow = tableRow
        self._cookies = cookies
        self._headers = headers[:]
        self._chainResults = {}
        self._enabled = enabled
        return

    # Roles are the index of the db role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self, roleIndex, enabled=False):
        self._roles[roleIndex] = enabled

    def addChainResultByMessageIndex(self, toID, toValue, chainIndex):
        if not toID in self._chainResults:
            self._chainResults[toID] = [(toValue, chainIndex)]
        else:
            self._chainResults[toID].append((toValue, chainIndex))

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

    def isEnabled(self):
        return self._enabled

    def toggleEnabled(self):
        self._enabled = not self._enabled



class RoleEntry:

    def __init__(self,index,columnIndex,name,deleted=False,singleUser=False):
        self._index = index
        self._name = name
        self._deleted = deleted
        self._column = columnIndex
        self._singleUser = singleUser
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

    def isSingleUser(self):
        return self._singleUser

class ChainEntry:

    TransformerList = ["base64","url","hex","sha1","sha256","sha512","md5"]
    
    def __init__(self, index, tableRow, name="", fromID="", fromRegex="", toID="", toRegex="", deleted=False, sourceUser=-1, enabled=True, transformers=[]):
        self._index = index
        self._fromID = fromID
        self._fromRegex = fromRegex
        self._toID = toID
        self._toRegex = toRegex
        self._deleted = deleted
        self._tableRow = tableRow
        self._name = name
        self._sourceUser = sourceUser
        self._fromStart = ""
        self._fromEnd = ""
        self._toStart = ""
        self._toEnd = ""
        self._enabled = enabled
        self._transformers = transformers[:] 

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
            self._fromRegex = self.getRexegFromStartAndEnd(self._fromStart,self._fromEnd)

    def setFromEnd(self, fromEnd):
        self._fromEnd = fromEnd
        if self._fromStart:
            self._fromRegex = self.getRexegFromStartAndEnd(self._fromStart,self._fromEnd)

    def setToStart(self, toStart):
        self._toStart = toStart
        if self._toEnd:
            self._toRegex = self.getRexegFromStartAndEnd(self._toStart,self._toEnd)

    def setToEnd(self, toEnd):
        self._toEnd = toEnd
        if self._toStart:
            self._toRegex = self.getRexegFromStartAndEnd(self._toStart,self._toEnd)

    def getRexegFromStartAndEnd(self,start,end):
        # TODO add this to the UI, perhaps with a right click option to change the table rows?
        return re.escape(start)+"(.*?)"+re.escape(end)

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

    def getSVName(self):
        # TODO access svPrefix from above
        if self._fromID.startswith("SV_"):
            return self._fromID[3:]
        return None

    def isEnabled(self):
        return self._enabled

    def toggleEnabled(self):
        self._enabled = not self._enabled

    def addTransformer(self, value):
        self._transformers.append(value)

    def clearTransformers(self):
        self._transformers=[]

    def transform(self, value, callbacks):
        ret = value
        if not ret:
            return ""
        try:
            for transformer in self._transformers:
                #self._transformerList = ["base64encode","urlencode","hexencode","sha1","sha256","sha512","md5"]
                if transformer == self.TransformerList[0]:
                    ret = base64.b64encode(ret.encode('utf-8'))
                elif transformer == self.TransformerList[1]:
                    ret = urllib.quote_plus(ret)
                elif transformer == self.TransformerList[2]:
                    ret = base64.b16encode(ret)
                elif transformer == self.TransformerList[3]:
                    ret = hashlib.sha1(ret).hexdigest()
                elif transformer == self.TransformerList[4]:
                    ret = hashlib.sha256(ret).hexdigest()
                elif transformer == self.TransformerList[5]:
                    ret = hashlib.sha512(ret).hexdigest()
                elif transformer == self.TransformerList[6]:
                    ret = hashlib.md5(ret).hexdigest()
        except:
            traceback.print_exc(file=callbacks.getStderr())
            return value
        return ret



class SVEntry:

    def __init__(self, name, userValues = {}):
        self._name=name
        self._userValues = userValues.copy()

    def setValueForUserIndex(self, userIndex, val):
        self._userValues[userIndex] = val

    def getValueForUserIndex(self, userIndex):
        if userIndex in self._userValues:
            return self._userValues[userIndex]
        return ""



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

class RowTransferHandler(TransferHandler):

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

        if isinstance(self._table, MessageTable):
            self._table.getModel()._db.moveMessageToRow(int(rowFrom), int(index))
        elif isinstance(self._table, UserTable):
            self._table.getModel()._db.moveUserToRow(int(rowFrom), int(index))


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
