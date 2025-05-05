from Wappalyzer import Wappalyzer, WebPage

def identify_technologies():
    url = input("URL to identify technologies: ")
    webpage = WebPage.new_from_url(url)
    wappalyzer = Wappalyzer.latest()
    technologies = wappalyzer.analyze(webpage)
    
    if len(technologies)>0:
        print("Technologies found:")
        for tech in technologies:
            print(f"- {tech}")
    else:
        print("There was not found any technology to the url")
