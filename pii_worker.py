"""Presidio analysis process. Started by pii_detector.PresidioWorker, never by mitmproxy itself.

Protocol: one JSON object per line on stdin/stdout, ASCII only.
  start:    python pii_worker.py '<json options>'
  worker -> {"ready": true} once the engine is loaded, or {"ready": false, "error": "<type>"}
  parent -> {"id": n, "texts": ["...", ...]}
  worker -> {"id": n, "spans": [[[start, end, "TYPE"], ...], ...]}  (one list per text)
No text, span value or exception message is written anywhere: only type names.
"""
import json
import os
import sys


def write(stream, obj):
    stream.write(json.dumps(obj, ensure_ascii=True, separators=(',', ':')) + '\n')
    stream.flush()


def build(options):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    lang = options['language']
    nlp = NlpEngineProvider(nlp_configuration={'nlp_engine_name': 'spacy', 'models': [
        {'lang_code': lang, 'model_name': options['model']}]}).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=[lang])
    score = options.get('score', 0.7)
    return lambda text: [[r.start, r.end, r.entity_type]
                         for r in analyzer.analyze(text=text, language=lang, score_threshold=score)]


def serve(analyse, source, sink):
    for line in source:
        message = None
        try:
            message = json.loads(line)
            texts = message['texts']
            if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
                raise ValueError('texts')
            write(sink, {'id': message['id'], 'spans': [analyse(t) for t in texts]})
        except Exception as error:
            write(sink, {'id': message.get('id') if isinstance(message, dict) else None,
                         'error': type(error).__name__})


def main():
    # Keep the protocol channel private: libraries printing to stdout must not corrupt it.
    sink = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='ascii')
    sys.stdout = sys.stderr
    try:
        analyse = build(json.loads(sys.argv[1]))
        analyse('warm up')
    except Exception as error:
        write(sink, {'ready': False, 'error': type(error).__name__})
        return 1
    write(sink, {'ready': True})
    serve(analyse, sys.stdin, sink)
    return 0


if __name__ == '__main__':
    sys.exit(main())
