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
from java.awt import GridLayout;
from java.io import ObjectOutputStream;
from java.io import FileOutputStream;
from java.io import ObjectInputStream;
from java.io import FileInputStream;
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
from javax.swing.table import AbstractTableModel;
from javax.swing.table import TableCellRenderer;
from javax.swing.table import JTableHeader;
from java.awt import Color;
from java.awt.event import MouseAdapter;
from java.awt.event import ActionListener;
import java.lang;

from org.python.core.util import StringUtil
from threading import Lock
from threading import Thread
import traceback
import re

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
        callbacks.setExtensionName("AuthMatrix - v0.6.0")

        # DB that holds everything users, roles, and messages
        self._db = MatrixDB()

        # For saving/loading config
        self._fc = JFileChooser()        

        # Used by ActionListeners
        # TODO: can these be removed by instantiating action listeners with variables?
        selfExtender = self
        self._selectedColumn = -1
        self._selectedRow = -1


        # Table of User entries
        self._userTable = UserTable(self, model = UserTableModel(self._db))
        roleScrollPane = JScrollPane(self._userTable)
        self._userTable.redrawTable()

        # Table of Request (AKA Message) entries
        self._messageTable = MessageTable(self, model = MessageTableModel(self._db))
        messageScrollPane = JScrollPane(self._messageTable)
        self._messageTable.redrawTable()


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
                    if type(component) is JTableHeader:
                        table = component.getTable()
                        column = component.columnAtPoint(e.getPoint())
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
            def replaceDomain(self, requestData, oldDomain, newDomain):
                reqstr = StringUtil.fromBytes(requestData)
                reqstr = reqstr.replace("Host: "+oldDomain, "Host: "+newDomain)
                newreq = StringUtil.toBytes(reqstr)
                return newreq

            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        messages = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)]
                    else:
                        messages = [selfExtender._db.getMessageByRow(rowNum) for rowNum in selfExtender._messageTable.getSelectedRows()]

                    ok, host, port, tls = selfExtender.changeDomainPopup()
                    if ok and host:
                        if not port:
                            port = 443 if tls else 80
                        for m in messages:
                            # TODO is replacing the host header appropriate here?
                            request = self.replaceDomain(m._requestResponse.getRequest(), m._requestResponse.getHttpService().getHost(), host)
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

        # Top pane
        topPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,roleScrollPane,messageScrollPane)

        # request tabs added to this tab on click in message table
        self._tabs = JTabbedPane()

        # Button pannel
        buttons = JPanel()
        runButton = JButton("Run", actionPerformed=self.runClick)
        newUserButton = JButton("New User", actionPerformed=self.getInputUserClick)
        newRoleButton = JButton("New Role", actionPerformed=self.getInputRoleClick)
        #debugButton = JButton("Debug", actionPerformed=self.printDB)
        saveButton = JButton("Save", actionPerformed=self.saveClick)
        loadButton = JButton("Load", actionPerformed=self.loadClick)
        clearButton = JButton("Clear", actionPerformed=self.clearClick)
        buttons.add(runButton)
        buttons.add(newUserButton)
        buttons.add(newRoleButton)
        #buttons.add(debugButton)
        buttons.add(saveButton)
        buttons.add(loadButton)
        buttons.add(clearButton)

        bottomPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._tabs, buttons)

        # Main Pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, topPane, bottomPane)
        


        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(topPane)
        callbacks.customizeUiComponent(bottomPane)
        callbacks.customizeUiComponent(messageScrollPane)
        callbacks.customizeUiComponent(roleScrollPane)
        callbacks.customizeUiComponent(self._messageTable)
        callbacks.customizeUiComponent(self._userTable)
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(buttons)

        self._splitpane.setResizeWeight(0.5)
        topPane.setResizeWeight(0.3)
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
                messageIndex = self._db.createNewMessage(self._callbacks.saveBuffersToTempFiles(messageInfo), 
                    self._helpers.analyzeRequest(messageInfo).getUrl())
                #self._messageTable.getModel().addRow(row)
            self._messageTable.redrawTable()

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
            outs = ObjectOutputStream(FileOutputStream(fileName))
            outs.writeObject(self._db.getSaveableObject())
            outs.close()

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
            
            ins = ObjectInputStream(FileInputStream(fileName))
            dbData=ins.readObject()
            ins.close()

            self._db.load(dbData,self)
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def clearClick(self,e):
        result = JOptionPane.showConfirmDialog(self._splitpane, "Clear AuthMatrix Configuration?", "Clear Config", JOptionPane.YES_NO_OPTION)
        if result == JOptionPane.YES_OPTION:
            self._db.clear()
            self._tabs.removeAll()
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def runClick(self,e):
        t = Thread(target=self.runMessagesThread)
        self._tabs.removeAll()
        t.start()


    def changeDomainPopup(self):
        hostField = JTextField(25)
        portField = JTextField(25)
        checkbox = JCheckBox()
        domainPanel = JPanel(GridLayout(0,1))

        firstline = JPanel()
        firstline.add(JLabel("Specify the details of the server to which the request will be sent."))
        domainPanel.add(firstline)
        secondline = JPanel()
        secondline.add(JLabel("Host: "))
        secondline.add(hostField)
        domainPanel.add(secondline)
        thirdline = JPanel()
        thirdline.add(JLabel("Port: "))
        thirdline.add(portField)
        domainPanel.add(thirdline)
        fourthline = JPanel()
        fourthline.add(checkbox)
        fourthline.add(JLabel("Use HTTPS"))
        domainPanel.add(fourthline)

        result = JOptionPane.showConfirmDialog(
            self._splitpane,domainPanel, "Configure target details", JOptionPane.OK_CANCEL_OPTION)
        cancelled = (result == JOptionPane.CANCEL_OPTION)
        if cancelled:
            return (False, None, None, False)
        return (True, hostField.getText(), portField.getText(), checkbox.isSelected())

    ##
    ## Methods for running messages and analyzing results
    ##

    def runMessagesThread(self, messageIndexes=None):
        # TODO timeout run
        self._db.lock.acquire()
        try:
            # Update original requests with any user changes
            self._messageTable.updateMessages()

            indexes = messageIndexes
            if not indexes:
                indexes = self._db.getActiveMessageIndexes()
            self.clearColorResults(indexes)
            for index in indexes:
                self.runMessage(index)
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
        finally:
            self._db.lock.release()
            self.colorCodeResults()

    # Replaces headers/cookies with user's token
    def getNewHeaders(self, requestInfo, newCookieString, newHeader):
        headers = requestInfo.getHeaders()

        # Handle Cookies
        if newCookieString:
            cookieHeader = "Cookie:"
            previousCookies = []
            # NOTE: getHeaders has to be called again here cuz of java references
            for header in requestInfo.getHeaders():
                # Find and remove existing cookie header
                if str(header).startswith(cookieHeader):
                    previousCookies = str(header)[len(cookieHeader):].replace(" ","").split(";")
                    headers.remove(header)

            newCookies = newCookieString.replace(" ","").split(";")
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
            headers.add(cookieHeader+" "+";".join(newCookies))

        # Handle Custom Header
        if newHeader:
            # TODO: Support multiple headers with a newline somehow
            # Remove previous HTTP Header
            colon = newHeader.find(":")
            if colon >= 0:
                # getHeaders has to be called again here cuz of java references
                for header in requestInfo.getHeaders():
                    # If the header already exists, remove it
                    if str(header).startswith(newHeader[0:colon+1]):
                        headers.remove(header)
            headers.add(newHeader)

        return headers

    # Add static CSRF token if available
    def getNewBody(self, requestInfo, reqBody, postargs):
        
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
            userEntry = self._db.arrayOfUsers[userIndex]
            newHeaders = self.getNewHeaders(requestInfo, userEntry._cookies, userEntry._header)
            newBody = self.getNewBody(requestInfo, reqBody, userEntry._postargs)
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
            index +=1

        # Grab all active roleIndexes that are checkboxed
        activeCheckBoxedRoles = [index for index in messageEntry._roles.keys() if messageEntry._roles[index] and not self._db.arrayOfRoles[index].isDeleted()]
        # Check Role Results of message
        for roleIndex in self._db.getActiveRoleIndexes():
            expectedResult = self.checkResult(messageEntry, roleIndex, activeCheckBoxedRoles)
            messageEntry.setRoleResultByRoleIndex(roleIndex, expectedResult)
                    
    def colorCodeResults(self):
        self._messageTable.redrawTable()

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
            # if user is not in this role, ignore it
            if not userEntry._roles[roleIndex]:
                ignoreUser = True

            else:
                # This is modified with the addition of Failure Regexes
                # If user is in any other role that should succeed (or should fail), then ignore it
                for index in self._db.getActiveRoleIndexes():
                    if not index == roleIndex and userEntry._roles[index]:
                        if (index in activeCheckBoxedRoles and not messageEntry.isFailureRegex()) or (index not in activeCheckBoxedRoles and messageEntry.isFailureRegex()):
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

                shouldSucceed = roleIndex in activeCheckBoxedRoles
                succeed = found if shouldSucceed else not found
                
                # Added logic for Failure Regexes
                expected = not succeed if messageEntry.isFailureRegex() else succeed

                if not expected:
                    return False
        return True

##
## DB Class that holds all configuration data
##

class MatrixDB():

    def __init__(self):
        # Holds all custom data
        # NOTE: consider moving these constants to a different class
        self.STATIC_USER_TABLE_COLUMN_COUNT = 4
        self.STATIC_MESSAGE_TABLE_COLUMN_COUNT = 3
        self.LOAD_TIMEOUT = 3.0
        self.FAILURE_REGEX_SERIALIZE_CODE = "|AUTHMATRIXFAILUREREGEXPREFIX|"
        self.COOKIE_HEADER_SERIALIZE_CODE = "|AUTHMATRIXCOOKIEHEADERSERIALIZECODE|"
        self.BURP_SELECTED_CELL_COLOR = Color(0xFF,0xCD,0x81)

        self.lock = Lock()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0

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
    def createNewMessage(self,messagebuffer,url):
        self.lock.acquire()
        messageIndex = self.arrayOfMessages.size()
        self.arrayOfMessages.add(MessageEntry(messageIndex, messageIndex - self.deletedMessageCount, messagebuffer, url))

        # Add all existing roles as unchecked
        for roleIndex in self.getActiveRoleIndexes():
            self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return messageIndex

    def clear(self):
        self.lock.acquire()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0
        self.lock.release()

    def load(self, db, extender):
        self.lock.acquire()
        self.arrayOfUsers = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfMessages = ArrayList()
        self.deletedUserCount = db.deletedUserCount
        self.deletedRoleCount = db.deletedRoleCount
        self.deletedMessageCount = db.deletedMessageCount

        for message in db.arrayOfMessages:
            if message._successRegex.startswith(self.FAILURE_REGEX_SERIALIZE_CODE):
                regex = message._successRegex[len(self.FAILURE_REGEX_SERIALIZE_CODE):]
                failureRegexMode=True
            else:
                regex = message._successRegex
                failureRegexMode=False
            messageEntry = RequestResponseStored(extender, message._host, message._port, message._protocol, message._requestData)
            self.arrayOfMessages.add(MessageEntry(
                message._index,
                message._tableRow,
                messageEntry,
                message._url, message._name, message._roles, regex, message._deleted, failureRegexMode))

        for role in db.arrayOfRoles:
            self.arrayOfRoles.add(RoleEntry(
                role._index,
                role._mTableColumn-3, # NOTE this is done to preserve compatability with older state files
                role._name,
                role._deleted))
        
        for user in db.arrayOfUsers:
            token = [""] if not user._token else user._token.split(self.COOKIE_HEADER_SERIALIZE_CODE)
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

    

    def getSaveableObject(self):
        # NOTE: might not need locks?
        self.lock.acquire()
        serializedMessages = []
        serializedRoles = []
        serializedUsers = []
        for message in self.arrayOfMessages:
            regex = self.FAILURE_REGEX_SERIALIZE_CODE+message._regex if message.isFailureRegex() else message._regex
            serializedMessages.append(MessageEntryData(
                message._index, 
                message._tableRow,
                message._requestResponse.getRequest(), 
                message._requestResponse.getHttpService().getHost(),
                message._requestResponse.getHttpService().getPort(),
                message._requestResponse.getHttpService().getProtocol(),
                message._url, message._name, message._roles, regex, message._deleted))
        for role in self.arrayOfRoles:
            serializedRoles.append(RoleEntryData(
                role._index,
                role._column+3, # NOTE this is done to preserve compatability with older state files
                role._column+3, # NOTE this is done to preserve compatability with older state files
                role._name,
                role._deleted))
        for user in self.arrayOfUsers:
            cookies = user._cookies if user._cookies else ""
            header = user._header if user._header else ""
            name = user._name if user._name else ""
            postargs = user._postargs if user._postargs else ""
            token = cookies + self.COOKIE_HEADER_SERIALIZE_CODE + header
            serializedUsers.append(UserEntryData(
                user._index,
                user._tableRow,
                name,
                user._roles,
                user._deleted,
                token,
                postargs))

        ret = MatrixDBData(serializedMessages,serializedRoles, serializedUsers, self.deletedUserCount, self.deletedRoleCount, self.deletedMessageCount)
        self.lock.release()
        return ret

    def getActiveUserIndexes(self):
        return [x._index for x in self.arrayOfUsers if not x.isDeleted()]

    def getActiveRoleIndexes(self):
        return [x._index for x in self.arrayOfRoles if not x.isDeleted()]

    def getActiveMessageIndexes(self):
        return [x._index for x in self.arrayOfMessages if not x.isDeleted()]

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

    def deleteUser(self,userIndex):
        self.lock.acquire()
        userEntry = self.arrayOfUsers[userIndex]
        if userEntry:
            userEntry._deleted = True
            self.deletedUserCount += 1
            if len(self.arrayOfUsers) > userIndex+1:
                for i in self.arrayOfUsers[userIndex+1:]:
                    i._tableRow -= 1
        self.lock.release()

    def deleteRole(self,roleIndex):
        self.lock.acquire()
        roleEntry = self.arrayOfRoles[roleIndex]
        if roleEntry:
            roleEntry._deleted = True
            self.deletedRoleCount += 1
            if len(self.arrayOfRoles) > roleIndex+1:
                for i in self.arrayOfRoles[roleIndex+1:]:
                    i.updateColumn(i.getColumn()-1)
        self.lock.release()

    def deleteMessage(self,messageIndex):
        self.lock.acquire()
        messageEntry = self.arrayOfMessages[messageIndex]
        if messageEntry:
            messageEntry._deleted = True
            self.deletedMessageCount += 1
            if len(self.arrayOfMessages) > messageIndex+1:
                for i in self.arrayOfMessages[messageIndex+1:]:
                    i._tableRow -= 1
        self.lock.release()

    # NOTE: If this method is unused, probably remove it?
    def getUserEntriesWithinRole(self, roleIndex):
        return [userEntry for userEntry in self.arrayOfUsers if userEntry._roles[roleIndex]]


##
## Tables and Table Models  
##
    
class UserTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return len(self._db.getActiveUserIndexes())

    def getColumnCount(self):
        return len(self._db.getActiveRoleIndexes())+self._db.STATIC_USER_TABLE_COLUMN_COUNT
        
    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "User"
        elif columnIndex == 1:
            return "Cookies"
        elif columnIndex == 2:
            return "HTTP Header"
        elif columnIndex == 3:
            return "HTTP Parameter (CSRF)"
        else:
            roleEntry = self._db.getRoleByColumn(columnIndex, 'u')
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        userEntry = self._db.getUserByRow(rowIndex)
        if userEntry:
            if columnIndex == 0:
                return str(userEntry._name)
            elif columnIndex == 1:
                return str(userEntry._cookies)
            elif columnIndex == 2:
                return str(userEntry._header)
            elif columnIndex == 3:
                return str(userEntry._postargs)
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
            if col == 0:
                userEntry._name = val
            elif col == 1:
                userEntry._cookies = val
            elif col == 2:
                userEntry._header = val
            elif col == 3:
                userEntry._postargs = val
            else:
                roleIndex = self._db.getRoleByColumn(col, 'u')._index
                userEntry.addRoleByIndex(roleIndex, val)

        self.fireTableCellUpdated(row,col)

    # Set checkboxes and role editable
    def isCellEditable(self, row, col):
        return True
        
    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex < self._db.STATIC_USER_TABLE_COLUMN_COUNT:
            return str
        else:
            return Boolean


class UserTable(JTable):

    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)
        return

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()
        
        # Resize
        # User Name
        self.getColumnModel().getColumn(0).setMinWidth(100);
        self.getColumnModel().getColumn(0).setMaxWidth(1000);

        # Cookie
        self.getColumnModel().getColumn(1).setMinWidth(300);
        self.getColumnModel().getColumn(1).setMaxWidth(1500);

        # Header
        self.getColumnModel().getColumn(2).setMinWidth(150);
        self.getColumnModel().getColumn(2).setMaxWidth(1500);

        # POST args
        self.getColumnModel().getColumn(3).setMinWidth(150);
        self.getColumnModel().getColumn(3).setMaxWidth(1500);

        self.getTableHeader().getDefaultRenderer().setHorizontalAlignment(JLabel.CENTER)


class MessageTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return len(self._db.getActiveMessageIndexes())
        
    def getColumnCount(self):
        return self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT+len(self._db.getActiveRoleIndexes())

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
        if col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-2:
            messageEntry._name = val
        elif col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
            messageEntry._regex = val
        else:
            roleIndex = self._db.getRoleByColumn(col, 'm')._index
            messageEntry.addRoleByIndex(roleIndex,val)
        if col >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
            messageEntry.clearResults()
            self.fireTableCellUpdated(row,col)
            # Update the chekbox colors since the results were deleted
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
                
        # TODO: do this on a tab change on extender._tabs: I think its needed for sending to repeater and comparer
        # WEIRD: I think this should make it so that only the original can be sent to places
        # However, it looks like it is working as expected... ???
        self._extender._currentlyDisplayedItem = selectedMessage._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
        return

    def createRequestTabs(self, requestResponse, original=False, index=-1):
        requestTabs = JTabbedPane()
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
            if requestViewer and requestViewer.isMessageModified():
                messageEntry = self.getModel()._db.arrayOfMessages[messageIndex]
                newMessage = requestViewer.getMessage()
                messageEntry._requestResponse = RequestResponseStored(self._extender, request=newMessage, httpService=messageEntry._requestResponse.getHttpService())                
        self._viewerMap = {}


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
                        failureRegexMode = messageEntry.isFailureRegex()

                        if sawExpectedResults:
                            # Set Green if success
                            if isSelected:
                                cell.setBackground(Color(0xC8,0xE0,0x51))
                            else:
                                cell.setBackground(Color(0x87,0xf7,0x17))
                        elif (checkboxChecked and not failureRegexMode) or (not checkboxChecked and failureRegexMode):
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

    def __init__(self, index, tableRow, requestResponse, url, name = "", roles = {}, regex = "^HTTP/1\\.1 200 OK", deleted = False, failureRegexMode = False):
        self._index = index
        self._tableRow = tableRow
        self._requestResponse = requestResponse
        self._url = url
        self._name = url.getPath() if not name else name
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

    def isDeleted(self):
        return self._deleted

    def updateTableRow(self, row):
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
        self._roles = roles
        self._deleted = deleted
        self._tableRow = tableRow
        self._cookies = cookies
        self._header = header
        self._postargs = postargs
        return

    # Roles are the index of the db role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self, roleIndex, enabled=False):
        self._roles[roleIndex] = enabled

    def isDeleted(self):
        return self._deleted

    def updateTableRow(self, row):
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

    def isDeleted(self):
        return self._deleted

    # NOTE: in v0.6 this value was changed to index into the dynamic columns only

    def updateColumn(self, column):
        self._column = column

    def getColumn(self):
        return self._column

##
## SERIALIZABLE CLASSES
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

    def __init__(self, index, tableRow, requestData, host, port, protocol, url, name, roles, successRegex, deleted):
        self._index = index
        self._tableRow = tableRow
        self._requestData = requestData
        self._host = host
        self._port = port
        self._protocol = protocol
        self._url = url
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



