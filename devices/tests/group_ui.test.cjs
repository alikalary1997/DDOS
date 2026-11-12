const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class El {
  constructor(tag='div'){ this.tag=tag; this.dataset={}; this.events={}; this.attributes={}; this.className=''; this.textContent=''; this.hidden=false; this.disabled=false; this.open=false; }
  addEventListener(e,f){ (this.events[e]=this.events[e]||[]).push(f); }
  setAttribute(k,v){ this.attributes[k]=v; } removeAttribute(k){ delete this.attributes[k]; }
  getAttribute(k){ return this.attributes[k]; }
  querySelector(){ return null; } querySelectorAll(){ return []; }
  showModal(){ this.open=true; } close(){ this.open=false; } focus(){ this.focused=true; }
  append(){}
  getBoundingClientRect(){ return {left:0,top:0,right:1,bottom:1}; }
}
function fixture(){
  const groupBtn = new El('button'); groupBtn.dataset.openGroup='';
  const groupDialog = new El('dialog');
  const nameInput = new El('input');
  const gform = new El('form');
  gform.querySelector = (s)=> s.includes('group_name') ? nameInput : null;
  groupDialog.querySelector = (s)=> s==='form' ? gform : null;
  const noop = new El();
  const doc = {
    getElementById: (id)=> ({addGroupDialog: groupDialog, addDeviceDialog:null, addDeviceForm:null,
      deviceSearch:noop, statusFilter:noop, typeFilter:noop, rawFilter:noop, groupFilter:noop,
      noMatchingDevices:noop, inventoryView:noop})[id] || null,
    querySelectorAll: (sel)=> sel==='[data-open-group]' ? [groupBtn] : [],
    querySelector: ()=> null,
    createElement: ()=> new El(),
    addEventListener(){},
  };
  const ctx = {document:doc, window:{addEventListener(){}}, console};
  vm.runInNewContext(fs.readFileSync('monitor/static/monitor/js/devices.js','utf8'), ctx);
  return {groupBtn, groupDialog, nameInput};
}
test('clicking + Group opens the group dialog and focuses the name field', () => {
  const f = fixture();
  assert.equal(f.groupDialog.open, false);
  f.groupBtn.events.click.forEach(fn=>fn());
  assert.equal(f.groupDialog.open, true);
  assert.equal(f.nameInput.focused, true);
  assert.equal(f.groupBtn.disabled, false);
});
