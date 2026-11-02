from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.quality_evaluation import score

class Quality(unittest.TestCase):
    def row(self,id,label,prediction,**kw):return dict(id=id,stage='confirmation',**{'class':'fixture'},label=label,prediction=prediction,**kw)
    def test_abstentions_are_retained_in_full_denominator_bounds(self):
        result=score([self.row('tp',True,'positive'),self.row('unknown-positive',True,'inconclusive'),self.row('unknown-negative',False,'inconclusive')])['by_stage_class'][0]
        self.assertEqual(result['sample_size'],3);self.assertEqual(result['inconclusive'],2);self.assertEqual(result['recall_bounds'],[.5,1]);self.assertEqual(result['false_positive_rate_bounds'],[0,1]);self.assertEqual(result['conditional_recall'],1)
    def test_all_four_cells_and_stage_separation(self):
        rows=[self.row(str(i),label,pred) for i,(label,pred) in enumerate([(True,'positive'),(True,'negative'),(False,'positive'),(False,'negative')])]
        rows.append(dict(self.row('other',True,'inconclusive'),stage='discovery'));result=score(rows)['by_stage_class']
        self.assertEqual(len(result),2);self.assertTrue(all(result[0][k]==1 for k in ('TP','FP','TN','FN')));self.assertEqual(result[0]['conditional_false_negative_rate'],.5)
    def test_leakage_duplicates_and_unlabeled_rows_refused(self):
        for rows in ([self.row('a',True,'positive',project='p',split='train'),self.row('b',False,'negative',project='p',split='test')],
                     [self.row('a',True,'positive'),self.row('a',False,'negative')],
                     [self.row('a',None,'inconclusive')]):
            with self.assertRaises(ValueError):score(rows)

if __name__=='__main__':unittest.main(verbosity=2)
