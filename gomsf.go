package gomsf

import (
	"bytes"
	"github.com/vmihailenco/msgpack"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type RPC struct {
	Host  string
	Port  int
	Token string
}

type resultStruct struct {
	Result bool
}

type errorStruct struct {
	Error                      bool
	Error_message, Error_class string
}

type coreVersionStruct struct {
	Version, Ruby string
}

type consoleStruct struct {
	Id, Prompt, Data string
	Busy             bool
}

type authLoginStruct struct {
	errorStruct
	resultStruct
}

type authTokenGenerateStruct struct {
	errorStruct
	resultStruct
	Token string
}

type coreModuleStatsStruct struct {
	Exploits, Auxiliary, Post, Encoders, Nops, Payloads int
}

type consoleWriteStruct struct {
	Wrote int
}

type datastoreStruct struct {
	EnableContextEncoding, DisablePayloadHandler, SSL   bool
	SSLVersion, SRVHOST, SRVPORT, PAYLOAD, LHOST, LPORT string
}

type jobStruct struct {
	Jid                       int
	Name, Start_time, Uripath string
	Datastore                 datastoreStruct
}

type moduleStruct struct {
	Name, Description, License, Filepath, Version string
	Rank                                          int
	References, Authors                           []string
}

type moduleOptionStruct struct {
	Type, Desc                           string
	Required, Advanced, Evasion, Default bool
	Enums                                []string
}

type encodedStruct struct {
	Encoded string
}

type sessionStruct struct {
	Type, Tunnel_local, Tunnel_peer, Via_exploit, Via_payload, Desc, Info, Workspace, Target_host, Username, Uuid, Exploit_uuid string
	Routes                                                                                                                      []string
}

type dataStruct struct {
	Data string
}

type seqStruct struct {
	Seq string
}

type shellReadStruct struct {
	dataStruct
	seqStruct
}

type shellWriteStruct struct {
	Write_count string
}

func (r *RPC) Call(args ...interface{}) map[string]interface{} {

	if args[0] != "auth.login" {
		// insert auth token as second argument
		args = append(args, 0)
		copy(args[1:], args[1:])
		args[1] = r.Token
	}

	encoded, err := msgpack.Marshal(args)

	if err != nil {

		log.Fatalln("error marshalling:", err)

	}

	httpClient := http.Client{}

	httpData := bytes.NewReader(encoded)

	httpReq, err := http.NewRequest("POST", "http://"+r.Host+":"+strconv.Itoa(r.Port)+"/api/1.0", httpData)

	if err != nil {
		log.Fatalln("error with httpreq:", err)
	}

	httpReq.Header.Add("Content-Type", "binary/message-pack")
	httpReq.Header.Add("Content-Length", string(len(encoded)))

	response, err := httpClient.Do(httpReq)

	if err != nil {
		log.Fatalln("request failed %v", err)
	}

	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatalln("reading body failed:", err)
	}

	var out map[string]interface{}

	err = msgpack.Unmarshal(body, &out)

	if err != nil {
		log.Fatalln("unmarshal failed:", err)
	}

	return out

}

func (r *RPC) AuthLogin(username, password string) (s authTokenGenerateStruct) {
	res := r.Call("auth.login", username, password)
	if res["error"] != nil && res["error"].(bool) == true {
		s.Error = res["error"].(bool)
		s.Error_class = res["error_class"].(string)
		s.Error_message = res["error_message"].(string)
	} else {
		s.Token = res["token"].(string)
	}
	return
}

func (r *RPC) AuthLogout() (s resultStruct) {
	res := r.Call("auth.logout", r.Token)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) AuthTokenAdd(newToken string) (s resultStruct) {
	res := r.Call("auth.token_add", newToken)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) AuthTokenGenerate() (s authTokenGenerateStruct) {
	res := r.Call("auth.token_generate")
	s.Token = res["token"].(string)
	return
}

func (r *RPC) AuthTokenList() (s []string) {
	res := r.Call("auth.token_list")["tokens"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) AuthTokenRemove(token string) (s resultStruct) {
	res := r.Call("auth.token_remove", token)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) CoreAddModulePath(path string) (s coreModuleStatsStruct) {
	res := r.Call("core.add_module_path", path)
	s.Exploits = res["exploits"].(int)
	s.Auxiliary = res["auxiliary"].(int)
	s.Post = res["post"].(int)
	s.Encoders = res["encoders"].(int)
	s.Nops = res["nops"].(int)
	s.Payloads = res["payloads"].(int)
	return
}

func (r *RPC) CoreModuleStats() (s coreModuleStatsStruct) {
	res := r.Call("core.module_stats")
	s.Exploits = res["exploits"].(int)
	s.Auxiliary = res["auxiliary"].(int)
	s.Post = res["post"].(int)
	s.Encoders = res["encoders"].(int)
	s.Nops = res["nops"].(int)
	s.Payloads = res["payloads"].(int)
	return
}

func (r *RPC) CoreReloadModules() (s coreModuleStatsStruct) {
	res := r.Call("core.reload_modules")
	s.Exploits = res["exploits"].(int)
	s.Auxiliary = res["auxiliary"].(int)
	s.Post = res["post"].(int)
	s.Encoders = res["encoders"].(int)
	s.Nops = res["nops"].(int)
	s.Payloads = res["payloads"].(int)
	return
}

func (r *RPC) CoreSave() (s resultStruct) {
	res := r.Call("core.save")
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) CoreSetg(optionName, optionValue string) (s resultStruct) {
	res := r.Call("core.setg", optionName, optionValue)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) CoreUnsetg(optionName string) (s resultStruct) {
	res := r.Call("core.unsetg", optionName)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) CoreThreadList() {
	panic("coreThreadList not implemented yet")
}

func (r *RPC) CoreThreadKill(threadId string) (s resultStruct) {
	res := r.Call("core.thread_kill", threadId)
	s.Result = res["result"].(bool)
	return
}

func (r RPC) CoreVersion() (s coreVersionStruct) {
	res := r.Call("core.version")
	s.Version = res["version"].(string)
	s.Ruby = res["ruby"].(string)
	return
}

func (r *RPC) CoreStop() (s resultStruct) {
	/* figure out how to fix this if the server stops before a response is received */
	res := r.Call("core.stop")
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) ConsoleCreate() (s consoleStruct) {
	res := r.Call("console.create")
	s.Id = res["id"].(string)
	s.Prompt = res["prompt"].(string)
	s.Busy = res["busy"].(bool)
	return
}

func (r *RPC) ConsoleDestroy(consoleId int) (s resultStruct) {
	res := r.Call("console.destroy", consoleId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) ConsoleList() (s []consoleStruct) {
	// res := r.Call("console.list")["consoles"].([]interface{})
	// for i := 0; i < len(res); i++ {
	// 	s = append(s, consoleStruct{
	// 					Id:     res[i]["id"].(string)
	// 					Prompt: res[i]["prompt"].(string),
	// 					Busy:   res[i]["busy"].(string),
	// 				})
	// }
	// return
	panic("consoleList not implemented")
}

func (r *RPC) ConsoleWrite(consoleId string, data string) (s consoleWriteStruct) {
	if strings.HasSuffix(data, `\n`) != true {
		data += `\n`
	}
	res := r.Call("console.write", consoleId, data)
	s.Wrote = res["wrote"].(int)
	return
}

func (r *RPC) ConsoleRead(consoleId string) (s consoleStruct) {
	res := r.Call("console.read", consoleId)
	s.Data = res["data"].(string)
	s.Prompt = res["prompt"].(string)
	s.Busy = res["busy"].(bool)
	return
}

func (r *RPC) ConsoleSessionDetach(consoleId string) (s resultStruct) {
	res := r.Call("console.session_detach", consoleId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) ConsoleSessionKill(consoleId string) (s resultStruct) {
	res := r.Call("console.session_kill", consoleId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) ConsoleTabs(consoleId string, inputLine string) (s []string) {
	res := r.Call("console.tabs", consoleId, inputLine)["tabs"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) JobList() (s map[int]string) {
	panic("jobList not implemented")
}

func (r *RPC) JobInfo(jobId string) (s jobStruct) {
	panic("jobInfo not implemented")
}

func (r *RPC) JobStop(jobId string) (s resultStruct) {
	res := r.Call("job.stop", jobId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) ModuleExploits() (s []string) {
	res := r.Call("module.exploits")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleAuxiliary() (s []string) {
	res := r.Call("module.auxiliary")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModulePost() (s []string) {
	res := r.Call("module.post")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModulePayloads() (s []string) {
	res := r.Call("module.payloads")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleEncoders() (s []string) {
	res := r.Call("module.encoders")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleNops() (s []string) {
	res := r.Call("module.nops")["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleInfo(moduleType, moduleName string) (s moduleStruct) {
	res := r.Call("module.info", moduleType, moduleName)
	s.Name = res["name"].(string)
	s.Description = res["description"].(string)
	s.License = res["license"].(string)
	s.Filepath = res["filepath"].(string)
	s.Version = res["version"].(string)
	s.Rank = res["rank"].(int)
	s.References = res["references"].([]string)
	s.Authors = res["authors"].([]string)
	return
}

func (r *RPC) ModuleOptions(moduleType, moduleName string) (s map[string]moduleOptionStruct) {
	panic("moduleOptions not implemented")
}

func (r *RPC) ModuleCompatiblePayloads(moduleName string) (s []string) {
	res := r.Call("module.compatible_payloads", moduleName)["payloads"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleTargetCompatiblePayloads(moduleName string, targetIndex int) (s []string) {
	res := r.Call("module.target_compatible_payloads", moduleName, targetIndex)["payloads"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleCompatibleSessions(moduleName string) (s []string) {
	res := r.Call("module.compatible_sessions", moduleName)["sessions"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) ModuleEncode(data, encoderModule string, options map[string]interface{}) (s encodedStruct) {
	for k, v := range options {
		options[k] = v.(string)
	}
	res := r.Call("module.encode", data, encoderModule, options)
	s.Encoded = res["encoded"].(string)
	return
}

func (r *RPC) ModuleExecute(moduleType, moduleName string, datastore map[string]interface{}) (s int) {
	for k, v := range datastore {
		datastore[k] = v.(string)
	}
	res := r.Call("module.execute", moduleType, moduleName, datastore)
	s = res["job_id"].(int)
	return
}

func (r *RPC) PluginLoad(pluginName string, options map[string]interface{}) (s resultStruct) {
	for k, v := range options {
		options[k] = v.(string)
	}
	res := r.Call("plugin.load", pluginName, options)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) PluginUnload(pluginName string) (s resultStruct) {
	res := r.Call("plugin.unload", pluginName)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) PluginLoaded() (s []string) {
	res := r.Call("plugin.loaded")["plugins"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) SessionList() (s map[int]sessionStruct) {
	panic("sessionList not implemented")
}

func (r *RPC) SessionStop(sessionId string) (s resultStruct) {
	res := r.Call("session.stop", sessionId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionShellRead(sessionId string) (s shellReadStruct) {
	res := r.Call("session.shell_read", sessionId)
	s.Seq = res["seq"].(string)
	s.Data = res["data"].(string)
	return
}

func (r *RPC) SessionShellWrite(sessionId, data string) (s shellWriteStruct) {
	res := r.Call("session.shell_write", sessionId, data)
	s.Write_count = res["write_count"].(string)
	return
}

func (r *RPC) SessionMeterpreterWrite(sessionId, data string) (s resultStruct) {
	res := r.Call("session.meterpreter_write", sessionId, data)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionMeterpreterRead(sessionId string) (s dataStruct) {
	res := r.Call("session.meterpreter_read", sessionId)
	s.Data = res["data"].(string)
	return
}

func (r *RPC) SessionMeterpreterSingleRun(sessionId, command string) (s resultStruct) {
	res := r.Call("session.meterpreter_single_run", sessionId, command)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionMeterpreterScript(sessionId, scriptName string) (s resultStruct) {
	res := r.Call("session.meterpreter_script", sessionId, scriptName)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionMeterpreterSessionDetach(sessionId string) (s resultStruct) {
	res := r.Call("session.meterpreter_session_detach", sessionId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionMeterpreterSessionKill(sessionId string) (s resultStruct) {
	res := r.Call("session.meterpreter_session_kill", sessionId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionMeterpreterTabs(sessionId, inputLine string) (s []string) {
	res := r.Call("session.meterpreters_tabs", sessionId, inputLine)["tabs"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) SessionCompatibleModules(sessionId string) (s []string) {
	res := r.Call("session.compatible_modules", sessionId)["modules"].([]interface{})
	for i := 0; i < len(res); i++ {
		s = append(s, res[i].(string))
	}
	return
}

func (r *RPC) SessionShellUpgrade(sessionId, connectHost, connectPort string) (s resultStruct) {
	res := r.Call("session.shell_upgrade", sessionId, connectHost, connectPort)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionRingClear(sessionId string) (s resultStruct) {
	res := r.Call("session.ring_clear", sessionId)
	s.Result = res["result"].(bool)
	return
}

func (r *RPC) SessionRingLast(sessionId string) (s seqStruct) {
	res := r.Call("session.ring_last", sessionId)
	s.Seq = res["seq"].(string)
	return
}

func (r *RPC) SessionRingPut(sessionId, data string) (s shellWriteStruct) {
	res := r.Call("session.ring_put", sessionId, data)
	s.Write_count = res["write_count"].(string)
	return
}

func (r *RPC) SessionRingRead(sessionId string) (s shellReadStruct) {
	res := r.Call("session.ring_read")
	s.Seq = res["seq"].(string)
	s.Data = res["data"].(string)
	return
}
