"""Stage-separated metrics with explicit abstentions; no discovery/field claims."""
from __future__ import annotations
from collections import defaultdict
import math

STAGES=frozenset({'discovery','confirmation','classification','duplicates','llm_triage','evidence_quality'})

def _wilson(successes,n):
    if not n:return None
    z=1.959963984540054;p=successes/n;denominator=1+z*z/n
    center=(p+z*z/(2*n))/denominator
    radius=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/denominator
    return [max(0,center-radius),min(1,center+radius)]

def score(records):
    """Each labeled row has id/stage/class/label and positive|negative|inconclusive prediction."""
    if not isinstance(records,list) or len(records)>50000:raise ValueError('bounded evaluation records required')
    groups=defaultdict(list);seen=set();projects=defaultdict(set)
    for row in records:
        if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not row['id'] or row['id'] in seen:raise ValueError('unique evaluation id required')
        seen.add(row['id'])
        if row.get('stage') not in STAGES or not isinstance(row.get('class'),str) or type(row.get('label')) is not bool or row.get('prediction') not in {'positive','negative','inconclusive'}:
            raise ValueError('explicit stage/class/boolean label/three-state prediction required')
        if row.get('split') is not None:
            if row['split'] not in {'train','tune','test'} or not isinstance(row.get('project'),str) or not row['project']:raise ValueError('project and recognized split required')
            projects[row['project']].add(row['split'])
        groups[(row['stage'],row['class'])].append(row)
    if any(len(v)>1 for v in projects.values()):raise ValueError('project leakage across train/tune/test splits')
    result=[]
    for (stage,kind),rows in sorted(groups.items()):
        counts=dict(TP=0,FP=0,TN=0,FN=0,inconclusive=0,inconclusive_positive=0,inconclusive_negative=0)
        for row in rows:
            if row['prediction']=='inconclusive':counts['inconclusive']+=1;counts['inconclusive_positive' if row['label'] else 'inconclusive_negative']+=1
            else:counts[('TP' if row['label'] else 'FP') if row['prediction']=='positive' else ('FN' if row['label'] else 'TN')]+=1
        tp,fp,tn,fn=(counts[k] for k in ('TP','FP','TN','FN'));ip,ineg=counts['inconclusive_positive'],counts['inconclusive_negative']
        ratio=lambda a,b:a/b if b else None
        positives=tp+fn+ip;negatives=tn+fp+ineg
        result.append({'stage':stage,'class':kind,**counts,'sample_size':len(rows),'prediction_coverage':(len(rows)-counts['inconclusive'])/len(rows),
            'conditional_precision':ratio(tp,tp+fp),'conditional_recall':ratio(tp,tp+fn),
            'conditional_false_positive_rate':ratio(fp,fp+tn),'conditional_false_negative_rate':ratio(fn,tp+fn),
            'recall_bounds':[ratio(tp,positives),ratio(tp+ip,positives)],
            'false_positive_rate_bounds':[ratio(fp,negatives),ratio(fp+ineg,negatives)],
            'false_negative_rate_bounds':[ratio(fn,positives),ratio(fn+ip,positives)],
            'precision_wilson_95':_wilson(tp,tp+fp),'recall_wilson_95_conditional':_wilson(tp,tp+fn),
            'interval_scope':'Descriptive binomial intervals for these rows; synthetic/dependent fixtures are not independent field samples.'})
    return {'schema':'tbhm.quality-evaluation/1','by_stage_class':result,'sample_size':len(records),
            'meaning':'Conditional metrics omit abstentions only in their explicitly named denominators; bounds retain every labeled row. Stages are not interchangeable. No general field accuracy follows.'}
