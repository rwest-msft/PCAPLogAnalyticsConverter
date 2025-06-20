import logging
import azure.functions as func
import os

app = func.FunctionApp()

@app.function_name(name="HttpTrigger1")
@app.route(route="test")
def test_function(req: func.HttpRequest) -> func.HttpResponse:
    """Test function to check environment variables and configuration"""
    try:
        logging.info('Test function processed a request.')
        
        # Check environment variables
        workspace_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID', 'NOT_SET')
        shared_key = os.environ.get('LOG_ANALYTICS_SHARED_KEY', 'NOT_SET')
        
        result = {
            'workspace_id': workspace_id,
            'shared_key_status': 'SET' if shared_key != 'NOT_SET' else 'NOT_SET',
            'shared_key_length': len(shared_key) if shared_key != 'NOT_SET' else 0
        }
        
        return func.HttpResponse(
            f"Environment check result: {result}",
            status_code=200
        )
    except Exception as e:
        logging.error(f"Error in test function: {str(e)}")
        return func.HttpResponse(
            f"Error: {str(e)}",
            status_code=500
        )
