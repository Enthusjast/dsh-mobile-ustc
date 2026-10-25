import test from 'node:test'
import assert from 'node:assert/strict'
import { configuredCreationOptions, creationOptionsSchema } from '../src/creation-options.js'

const workspace='88888888-8888-4888-8888-888888888888'
test('creation choices expose explicit public labels and allowed tokens without local paths',()=>{
  const options=configuredCreationOptions([{id:'private-local-reference',cwd:'/private/do-not-publish',remoteId:workspace,label:'研究项目'}],['standard','review','standard','../unsafe'])
  assert.deepEqual(options,{workspaces:[{workspace_id:workspace,label:'研究项目'}],presets:['standard','review']})
  assert.equal(JSON.stringify(options).includes('/private'),false); assert.equal(JSON.stringify(options).includes('private-local-reference'),false)
})
test('ambiguous remote workspace mappings and local-only workspaces cannot become creation choices',()=>{
  const options=configuredCreationOptions([{id:'one',cwd:'/one',remoteId:workspace},{id:'two',cwd:'/two',remoteId:workspace},{id:'local',cwd:'/local'}],['standard'])
  assert.deepEqual(options.workspaces,[])
})
test('metadata labels and counts retain bounded scalar Unicode and reject hidden fields',()=>{
  for(const label of [' ','bad\u0000','\ud800','中'.repeat(33)]) assert.equal(creationOptionsSchema.safeParse({workspaces:[{workspace_id:workspace,label}],presets:['standard']}).success,false)
  assert.equal(creationOptionsSchema.safeParse({workspaces:[{workspace_id:workspace,label:'研究🙂',cwd:'/leak'}],presets:['standard']}).success,false)
  assert.equal(creationOptionsSchema.safeParse({workspaces:[],presets:Array.from({length:129},(_,i)=>`preset${i}`)}).success,false)
})
