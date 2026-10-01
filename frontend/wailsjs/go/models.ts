export namespace analysis {
	
	export class Counts {
	    process: number;
	    file_read: number;
	    file_write: number;
	    file_create: number;
	    file_delete: number;
	    network: number;
	    dns: number;
	    download: number;
	    upload: number;
	    sensitive: number;
	    credential: number;
	    shell: number;
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new Counts(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.process = source["process"];
	        this.file_read = source["file_read"];
	        this.file_write = source["file_write"];
	        this.file_create = source["file_create"];
	        this.file_delete = source["file_delete"];
	        this.network = source["network"];
	        this.dns = source["dns"];
	        this.download = source["download"];
	        this.upload = source["upload"];
	        this.sensitive = source["sensitive"];
	        this.credential = source["credential"];
	        this.shell = source["shell"];
	        this.total = source["total"];
	    }
	}
	export class ProcessNode {
	    pid: number;
	    ppid: number;
	    command_line: string;
	    executable?: string;
	    children?: ProcessNode[];
	
	    static createFrom(source: any = {}) {
	        return new ProcessNode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.ppid = source["ppid"];
	        this.command_line = source["command_line"];
	        this.executable = source["executable"];
	        this.children = this.convertValues(source["children"], ProcessNode);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimelineItem {
	    timestamp: string;
	    type: string;
	    pid: number;
	    target: string;
	    risk?: string;
	    mode: string;
	    decision: string;
	
	    static createFrom(source: any = {}) {
	        return new TimelineItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.type = source["type"];
	        this.pid = source["pid"];
	        this.target = source["target"];
	        this.risk = source["risk"];
	        this.mode = source["mode"];
	        this.decision = source["decision"];
	    }
	}

}

export namespace main {
	
	export class EventInfo {
	    ts: string;
	    type: string;
	    category: string;
	    action: string;
	    pid: number;
	    ppid: number;
	    target: string;
	    risk: string;
	    mode: string;
	    decision: string;
	
	    static createFrom(source: any = {}) {
	        return new EventInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ts = source["ts"];
	        this.type = source["type"];
	        this.category = source["category"];
	        this.action = source["action"];
	        this.pid = source["pid"];
	        this.ppid = source["ppid"];
	        this.target = source["target"];
	        this.risk = source["risk"];
	        this.mode = source["mode"];
	        this.decision = source["decision"];
	    }
	}
	export class ReportInfo {
	    session_id: string;
	    mode: string;
	    status: string;
	    counts: analysis.Counts;
	    process_tree: analysis.ProcessNode[];
	    sensitive_events: analysis.TimelineItem[];
	
	    static createFrom(source: any = {}) {
	        return new ReportInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.session_id = source["session_id"];
	        this.mode = source["mode"];
	        this.status = source["status"];
	        this.counts = this.convertValues(source["counts"], analysis.Counts);
	        this.process_tree = this.convertValues(source["process_tree"], analysis.ProcessNode);
	        this.sensitive_events = this.convertValues(source["sensitive_events"], analysis.TimelineItem);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SessionInfo {
	    id: string;
	    sandbox_id: string;
	    agent_id: string;
	    agent: string;
	    workdir: string;
	    mode: string;
	    status: string;
	    started_at: string;
	    exit_code?: number;
	    root_pid?: number;
	
	    static createFrom(source: any = {}) {
	        return new SessionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.sandbox_id = source["sandbox_id"];
	        this.agent_id = source["agent_id"];
	        this.agent = source["agent"];
	        this.workdir = source["workdir"];
	        this.mode = source["mode"];
	        this.status = source["status"];
	        this.started_at = source["started_at"];
	        this.exit_code = source["exit_code"];
	        this.root_pid = source["root_pid"];
	    }
	}

}

