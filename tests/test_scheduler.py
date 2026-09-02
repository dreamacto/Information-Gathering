from authorized_assessment.orchestration.graph_builder import GraphBuilder
from authorized_assessment.orchestration.scheduler import Scheduler


def graph():
    b=GraphBuilder("graph_test","asmt","wz",cursor_file="phase_status.json")
    a=b.add_node("a"); c=b.add_node("c"); b.add_edge(a,c); return b.build()


def test_scheduler_dependency_and_retry():
    calls=[]
    def dispatch(node, attempt):
        calls.append((node.phase, attempt))
        if node.phase == "a" and attempt == 1: return {"error_class":"timeout"}
        return {"status":"ok"}
    g=GraphBuilder("graph_test","asmt","wz",cursor_file="phase_status.json")
    a=g.add_node("a", retry_limit=1); c=g.add_node("c"); g.add_edge(a,c)
    result=Scheduler(g.build(), dispatch).run()
    assert result.status == "completed" and calls == [("a",1),("a",2),("c",1)]


def test_scheduler_invalid_dispatch_is_blocked():
    result=Scheduler(graph(), lambda n,a: {"error_class":"permission_denied"}).run()
    assert result.status == "blocked"
