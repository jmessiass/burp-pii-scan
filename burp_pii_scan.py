# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener, IScanIssue

def validate_cpf(cpf):
    # check if all digits are the same (11111111111)
    if cpf == cpf[0] * 11:
        return False

    # calculate the first check digit
    sum_ = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digit1 = 11 - (sum_ % 11)
    digit1 = 0 if digit1 >= 10 else digit1

    # calculate the second check digit
    sum_ = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digit2 = 11 - (sum_ % 11)
    digit2 = 0 if digit2 >= 10 else digit2

    # check if the calculated digits match the provided digits
    return cpf[-2:] == "{}{}".format(digit1, digit2)

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # initial configs
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PII Scanner")
        callbacks.registerHttpListener(self)
        print("PII Scanner, Installation OK!!!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # process http response
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # extract body response
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # looking for cpf and validate
            cpf_pattern = re.compile(r'\b\d{11}\b') # extract 11 numbers together
            possible_cpf = cpf_pattern.findall(body)
            possible_cpf = list(set(possible_cpf)) # remove duplicated
            cpf_ok = [cpf for cpf in possible_cpf if validate_cpf(cpf)]

            if cpf_ok: # if found cpf, create issue
                print("CPF: %s" % cpf_ok[0])
                http_service = messageInfo.getHttpService()
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                issue_name = "PII data detect"
                issue_detail = "Was found a PII data - CPF: %s " % cpf_ok[0]
                severity = "High"
                confidence = "Certain"
                remediation = "Mask the first 6 number and show just the last 5 numbers."

                issue = CustomScanIssue(
                    http_service,
                    url,
                    [messageInfo],
                    issue_name,
                    issue_detail,
                    severity,
                    confidence,
                    remediation
                )
                
                self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence, remediation):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0
    
    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service
    