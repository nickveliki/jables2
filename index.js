const fs = require("fs");
const pathreq = require("path");
const crypto = require("crypto");
const {totalmem} = require("os");
let _basePath;
let _secdatpath;
let _memoryQuota;
let _logfile;
let toWrite = false;
const db = {}
const del = {};
const log = (text)=>{
    fs.writeFileSync(pathreq.join(_basePath, _logfile), new Date().toUTCString()+": "+(typeof(text)=="object"?JSON.stringify(text):text)+"\n", {flag:"a", mode:0o600})
}
const QuotaReached = ()=>_memoryQuota<=1?process.memoryUsage().rss/totalmem()>_memoryQuota:process.memoryUsage().rss>_memoryQuota*Math.pow(2, 20);
const setup = (rel, secdatpath, writeinterval=60, memoryQuota=0.2, logfile="j2.log")=>new Promise((res, rej)=>{
    _secdatpath=secdatpath;
    _logfile = logfile;
    _basePath=pathreq.join(pathreq.resolve("./"), rel)
    _memoryQuota=memoryQuota;                
    fs.access(secdatpath, fs.constants.F_O|fs.constants.R_OK, (err)=>{
        if(err){
            const key= crypto.randomBytes(16)
            const iv = crypto.randomBytes(16)
            fs.writeFile(secdatpath, JSON.stringify({key: key.toString("base64"), iv: iv.toString("base64")}), {mode:0o600}, (message)=>{
                if(message){
                    rej({error: 500, message})
                }else{
                    fs.mkdir(_basePath, {recursive:true}, (err)=>{
                        if(err){
                            rej({error: 500, err: message})
                        }else{
                            fs.writeFile(pathreq.join(_basePath, "definitions.jdf"), crypto.createCipheriv("aes-128-gcm", key, iv).update(JSON.stringify({Definitions:[]})), (err)=>{
                                if(err){
                                    rej({error: 500, message: err});
                                }else{
                                    res()
                                }
                            })
                        }
                    })
                    setInterval(()=>{
                        writeDB()
                    }, writeinterval*1000)
                }
            })
        }else{
            getDB().then(()=>{
                setInterval(()=>{
                    writeDB()
                }, writeinterval*1000);
                res()
            }, rej)
        }        
    })
})
const getSec = ()=>new Promise((res, rej)=>{
    fs.readFile(_secdatpath, (err, data)=>{
        if(err){
            rej({error: 500, message: err})
        }else{
            const {key, iv} = JSON.parse(data.toString())
            res({key: Buffer.from(key, "base64"), iv:Buffer.from(iv, "base64")})
        }
    })
})
const getDB = ()=>new Promise((res, rej)=>{
    fs.readFile(pathreq.join(_basePath, "definitions.jdf"), (err, data)=>{
        if(err){
            log(err)
            res()
        }else{
            getSec().then(({key, iv})=>{
                let finished = 0;
                const {Definitions} = JSON.parse(crypto.createDecipheriv("aes-128-gcm", key, iv).update(data).toString())
                if(Definitions.length==0){
                    res()
                }
                Definitions.forEach((definition)=>{
                    const [path, iv] = definition.split("#");
                    fs.readFile(path, (err, data)=>{
                        if(!err){
                            const piv = iv.includes(",")?Buffer.from(iv.split(",").map((item)=>parseInt(item))):Buffer.from(iv, "base64");
                            const {indexKey, Versions} = JSON.parse(crypto.createDecipheriv("aes-128-gcm", key, piv).update(data).toString());
                            let table = {indexKey}
                            let quotad;
                            if(!QuotaReached()){
                                table["Versions"] = Versions;
                            }else{
                                quotad=true;
                                table["Versions"]=Versions.map((item)=>{
                                    const rs = {};
                                    rs[indexKey] = item[indexKey]
                                    return rs;
                                });
                            }
                            db[path.replace(_basePath+pathreq.sep, "").replace(".jdf", "").replace(/\\/g, "/").split("#")[0]]={iv: piv, table, quotad}
                        }else{
                            log(err)
                        }
                        finished++;
                        if(finished==Definitions.length){
                            res();
                        }
                    })
                })
            }, rej)
        }
    })
})
const writeDB = ()=>new Promise((res)=>{
    if(toWrite){
        getSec().then(({key, iv})=>{
            const Definitions = []
            const keys = Object.keys(db)
            if(keys.length){
                let finished = 0;
                keys.forEach((item)=>{
                    const p = pathreq.join(_basePath, item);
                    Definitions.push(`${p}.jdf#${db[item].iv.toString("base64")}`);
                    if(!fs.existsSync(pathreq.join(_basePath, ...item.split("/").splice(0, item.split("/").length-1)))){
                        fs.mkdirSync(pathreq.join(_basePath, ...item.split("/").splice(0, item.split("/").length-1)), {recursive:true})
                    }
                    fs.readFile(p+".jdf", (err, data)=>{
                        const table = {indexKey: db[item].table.indexKey, Versions: []}
                        if(err){
                            fs.writeFileSync(pathreq.join(_basePath, "error.log"), JSON.stringify({time: new Date().toUTCString(), err}), {flag:"a"})
                            table.Versions=db[item].table.Versions;
                        }else{
                            const searchKey = db[item].table.indexKey;
                            const fromFile = JSON.parse(crypto.createDecipheriv("aes-128-gcm", key, db[item].iv).update(data)).Versions.map((it)=>{
                                const searchValue=it[searchKey];
                                const {i, before} = searchArray(searchKey, searchValue, db[item].table.Versions)
                                if(before!=undefined){
                                    return it
                                }else{
                                    return updateObject(it, db[item].table.Versions.splice(i, 1)[0])
                                }
                            })
                            table.Versions=[...fromFile, ...db[item].table.Versions].filter((it)=>{
                                if(del[item]){
                                    const {i, before} = searchArray(searchKey, it[searchKey], del[item]);
                                    if(before==undefined){
                                        del[item].splice(i, 1);
                                        return false
                                    }
                                }
                                return true
                            }).sort((a, b)=>a[searchKey]<b[searchKey]?-1:1);
                            if(QuotaReached()){
                                db[item].table.Versions=table.Versions.map((item)=>{
                                    const res = {};
                                    res[searchKey]=item[searchKey]
                                    return res
                                })
                                db[item].quotad=true;
                            }else{
                                db[item].table.Versions=table.Versions
                                db[item].quotad=undefined
                            }
                        }
                        fs.writeFile(p+".jdf", crypto.createCipheriv("aes-128-gcm", key, db[item].iv).update(JSON.stringify(table)), {mode:0o600}, (err)=>{
                            if(err){
                                fs.writeFileSync(pathreq.join(_basePath, "error.log"), JSON.stringify({time: new Date().toUTCString(), err}), {flag:"a"})
                            }
                            finished++
                            if(finished==keys.length+1){
                                res()
                            }
                        })
                    })
                    
                })
                fs.writeFile(pathreq.join(_basePath, "definitions.jdf"), crypto.createCipheriv("aes-128-gcm", key, iv).update(JSON.stringify({Definitions})), (err)=>{
                    if(err){
                        fs.writeFileSync(pathreq.join(_basePath, "error.log"), JSON.stringify({time: new Date().toUTCString(), err}), {flag:"a"})
                    }
                    finished++
                    if(finished==keys.length+1){
                        res()
                    }
                })
            }else{
                res()
            }
            
        }, res)
        toWrite=false;
    }else{
        res();
    }
})
const searchArray = (searchkey, searchvalue, array)=>{
    if(array.length>0){
        let search = array.map((item)=>item);
        let bound = Math.round(search.length/2);
            while(search.length>1){
                if (searchvalue<search[bound][searchkey]){
                search.splice(bound, search.length-bound);
                }else{
                search.splice(0, bound);
            }
            bound=Math.round(search.length/2);
        }
        return {before: searchvalue!=search[0][searchkey]?searchvalue<search[0][searchkey]:undefined , i: array.indexOf(search[0])}
    }
    return {before: true, i: 0}
}
const getDefinitionSync = (definition)=>{
    if(typeof(definition)=="string"&&db[definition]){
        return db[definition].table;
    }else if (definition.path&&db[definition.path]&&definition[db[definition.path].table.indexKey]!=undefined){
        const {i, before} = searchArray(db[definition.path].table.indexKey, definition[db[definition.path].table.indexKey], db[definition.path].table.Versions)
        return before!=undefined?undefined:db[definition.path].table.Versions[i];
    }else{
        return undefined;
    }
}
const getDefinition = (definition)=>new Promise((res, rej)=>{
    const sync = getDefinitionSync(definition)
    if(sync){
        if(sync.indexKey){
            if(db[definition].quotad){
                getSec().then(({key})=>{
                    fs.readFile(pathreq.join(_basePath, definition+".jdf"), (err, data)=>{
                        if(err){
                            res(sync)
                        }else{
                            res(JSON.parse(crypto.createDecipheriv("aes-128-gcm", key, db[definition].iv).update(data).toString()))
                        }
                    })
                })
            }else{
                res(sync)
            }
        }else{
            if(Object.keys(sync).length==1){
                getDefinition(definition.path).then(({Versions})=>{
                    const {i, before} = searchArray(Object.keys(sync)[0], sync[Object.keys(sync)[0]], Versions);
                    const ibefore = searchArray(Object.keys(sync)[0], sync[Object.keys(sync)[0]], db[definition.path].table.Versions);
                    if(before==undefined){
                        db[definition.path].table.Versions.splice(ibefore.i, 1, Versions[i])
                        res(Versions[i])
                    }else{
                        rej({error: 404})
                    }
                }, rej)
            }else{
                res(sync)
            }
        }
    }else{
        rej({error: 404, message:"not found"})
    }
})
const updateObject = function(){
    const res = {};
    Array.from(arguments).forEach((argument)=>{
        Object.keys(argument).forEach((key)=>{
            res[key]=argument[key]
        })
    })
    return res;
}
const writeDefinition = (definition)=>{
    if(Array.isArray(definition)){
        definition.forEach(writeDefinition)
    }else{
        if(definition.path){
            if(db[definition.path]){
                if(definition[db[definition.path].table.indexKey]!=undefined){
                    const {i, before } = searchArray(db[definition.path].table.indexKey, definition[db[definition.path].table.indexKey], db[definition.path].table.Versions);
                    db[definition.path].table.Versions.splice(before==undefined?i:before?i:i+1, before==undefined?1:0, updateObject(before==undefined?db[definition.path].table.Versions[i]:{}, definition, {path: undefined, indexKey: undefined}))
                    toWrite=true;
                }
            }else if(definition.indexKey&&definition[definition.indexKey]!=undefined){
                db[definition.path]={iv:crypto.randomBytes(16), table:{indexKey: definition.indexKey, Versions: [updateObject(definition, {path: undefined, indexKey: undefined})]}}
                console.log(db)
                toWrite=true;
            }
        }
    }
}
const deleteDefinition = (definition)=>{
    if(Array.isArray(definition)){
        definition.forEach(deleteDefinition)
    }else{
        if(definition.path&&db[definition.path]&&definition[db[definition.path].table.indexKey]!=undefined){
            const {i, before} = searchArray(db[definition.path].table.indexKey, definition[db[definition.path].table.indexKey], db[definition.path].table.Versions);
            if(del[definition.path]){
                const delpar = searchArray(db[definition.path].table.indexKey, definition[db[definition.path].table.indexKey], del[definition.path])
                    if(before==undefined){
                    const delitem = db[definition.path].table.Versions.splice(i, 1);
                    const tdel = {};
                    tdel[db[definition.path].table.indexKey] = delitem[db[definition.path].table.indexKey];
                    del[definition.path].splice(delpar.before?delpar.i:delpar.i+1, 0, tdel)
                    toWrite=true
                }    
            }else if(before==undefined){
                del[definition.path] = [db.definition.path].table.Versions.splice(i, 1)   
            }
            
        }
    }
}
const getDefinitionProperty = (definition, property)=>new Promise((res, rej)=>{
    if(typeof(definition)=="string"&&typeof(property)!="number"&&parseInt(property)==NaN){
        rej({error: 409, message:"string definition must come with number property"})
    }else{
        getDefinition(definition).then((Version)=>{
            if(Version.Versions){
                res(Version.Versions[parseInt(property)])
            }else if (Version){
                res(Version[property]);
            }
        }, rej) 
    }
})
const importTables = (path, secDatPath)=>new Promise((res, rej)=>{
    fs.stat(path, (err, stat)=>{
        if(err){
            rej({error: 500, message: err})
        }else{
            if(stat.isDirectory()){
                fs.stat(secDatPath, (err, stat)=>{
                    if(err){
                        rej({error: 500, message: err})
                    }else{
                        if(stat.isFile()){
                            fs.readFile(secDatPath, (err, data)=>{
                                if(err){
                                    rej({error:500, message: err})
                                }else{
                                    const {key, iv} = JSON.parse(data.toString())
                                    fs.readFile(pathreq.join(path, "definitions.jdf"), (err, data)=>{
                                        if(err){
                                            rej({error: 409, message:"path must contain definitions.jdf and you must have rights for access"})
                                        }else{
                                            const {Definitions} = JSON.parse(crypto.createDecipheriv("aes-128-gcm", Buffer.from(key, "base64"), Buffer.from(iv, "base64")).update(data).toString())
                                            fs.readdir(path, (err, files)=>{
                                                if(err){
                                                    rej({error:500, message: err})
                                                }else{
                                                    const file = files.find((item)=>item!="definitions.jdf"&&item.endsWith(".jdf"))
                                                    const fullpath = Definitions.find((definition)=>definition.split("#")[0].endsWith(file))
                                                    const oldpath = fullpath.split(file)[0];
                                                    let finished = 0;
                                                    Definitions.forEach((definition)=>{
                                                        fs.readFile(pathreq.join(path, definition.split("#")[0].replace(oldpath, "")), (err, data)=>{
                                                            if(err){
                                                                log(err)
                                                            }else{
                                                                const [, iv] = definition.split("#");
                                                                const piv = iv.includes(",")?Buffer.from(iv.split(",").map((item)=>parseInt(item))):Buffer.from(iv, "base64");
                                                                const table = JSON.parse(crypto.createDecipheriv("aes-128-gcm", Buffer.from(key, "base64"), piv).update(data).toString());
                                                                writeDefinition(table.Versions.map((item)=>updateObject(item, {path: definition.replace(oldpath, "").replace(".jdf", "").replace(/\\/g, "/").split("#")[0], indexKey: table.indexKey})))
                                                            }
                                                            finished++
                                                            if(finished==Definitions.length){
                                                                res()
                                                            }
                                                        })
                                                    })
                                                }
                                            })

                                        }
                                    })
                                }
                            })
                        }else{
                            rej({error: 409, message:"must reference a file"})
                        }
                    }
                })
            }else{
                rej({error:409, message:"path to database to be imported must reference a directory"})
            }    
        }
    })
})
const exists = (definition)=>{
    const something = getDefinitionSync(definition);
    if (!something||something.Versions){
        return false
    }
    return true
}
module.exports={
    setup,
    getDefinition,
    updateObject,
    writeDefinition,
    deleteDefinition,
    getDefinitionProperty,
    importTables,
    writeDB,
    exists
}
